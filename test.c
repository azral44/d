/*
 * WiFi Auditor GUI (GTK3, C Only)
 * Author: azral44 (for educational purposes, CEH)
 * Note: This tool is for lawful security testing only.
 * Requirements: gcc, GTK3, pthread, airodump-ng, aireplay-ng, aircrack-ng
 * Compile: gcc wifi_auditor_gtk3.c -o wifi_auditor `pkg-config --cflags --libs gtk+-3.0` -lpthread
 */

#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_NETWORKS 256
#define MAX_HANDSHAKES 128

// ==== Signal Icon Helper ====
const char* get_signal_icon(const char *signal_dbm) {
    int pwr = atoi(signal_dbm);
    if (pwr >= -50) return "network-wireless-signal-excellent";
    if (pwr >= -60) return "network-wireless-signal-good";
    if (pwr >= -70) return "network-wireless-signal-ok";
    if (pwr >= -80) return "network-wireless-signal-weak";
    return "network-wireless-signal-none";
}

typedef struct {
    char ssid[64];
    char bssid[32];
    char enc[32];
    char cipher[32];
    char wps[8];
    char channel[8];
    char signal[8];
} wifi_network_t;

typedef struct {
    char filename[128];
    char ssid[64];
    char bssid[32];
    char channel[8];
} handshake_t;

static wifi_network_t networks[MAX_NETWORKS];
static int network_count = 0;
static handshake_t handshakes[MAX_HANDSHAKES];
static int handshake_count = 0;
static bool scanning = false;
static bool capturing_handshake = false;
static char monitor_iface[32] = "";
static char cap_bssid[32] = "";
static char cap_channel[8] = "";
static char cap_file[128] = "";
static pthread_t scan_thread, capture_thread;
static GtkWidget *treeview, *notif_label, *iface_combo, *handshake_treeview, *main_window;
static GtkListStore *store, *handshake_store;

// ==== GTK Thread-Safe GUI Update Helpers ====
gboolean update_networks_gui(gpointer data) {
    gtk_list_store_clear(store);
    for (int i = 0; i < network_count; ++i) {
        GtkTreeIter iter;
        gtk_list_store_append(store, &iter);
        char sec[128];
        snprintf(sec, sizeof(sec), "%s (%s)", networks[i].enc, networks[i].cipher);
        gtk_list_store_set(store, &iter,
            0, networks[i].ssid,
            1, networks[i].bssid,
            2, sec,
            3, networks[i].wps,
            4, networks[i].channel,
            5, get_signal_icon(networks[i].signal),
            -1);
    }
    return FALSE;
}
typedef struct {
    char notif[256];
} notif_data_t;
gboolean update_notification_main(gpointer data) {
    notif_data_t *d = (notif_data_t*)data;
    gtk_label_set_text(GTK_LABEL(notif_label), d->notif);
    free(d);
    return FALSE;
}
void set_notification_threadsafe(const char *msg) {
    notif_data_t *d = malloc(sizeof(notif_data_t));
    strncpy(d->notif, msg, sizeof(d->notif)-1); d->notif[sizeof(d->notif)-1]=0;
    g_idle_add(update_notification_main, d);
}
// For handshake tab
typedef struct {
    handshake_t h;
} handshake_add_data_t;
gboolean add_handshake_gui(gpointer data) {
    handshake_add_data_t *d = (handshake_add_data_t*)data;
    GtkTreeIter iter;
    gtk_list_store_append(handshake_store, &iter);
    gtk_list_store_set(handshake_store, &iter,
        0, d->h.ssid,
        1, d->h.bssid,
        2, d->h.channel,
        3, d->h.filename,
        -1);
    free(d);
    return FALSE;
}




// ==== CSV Parsing (airodump-ng) ====
void parse_airodump_csv(const char *csv_file) {
    FILE *fp = fopen(csv_file, "r");
    if (!fp) return;
    char line[512];
    bool reading = false;
    network_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!reading && strstr(line, "BSSID,")) {
            reading = true;
            continue;
        }
        if (reading && strlen(line) > 10 && line[0] != '\n' && line[0] != '\r') {
            char bssid[32] = "", ch[8] = "", enc[32] = "", cipher[32] = "", essid[64] = "", pwr[8] = "", wps[8] = "No";
            int n = sscanf(line, "%31[^,],%*[^,],%*[^,],%7[^,],%*[^,],%31[^,],%31[^,],%*[^,],%7[^,],%*[^,],%*[^,],%*[^,],%*[^,],%63[^,],",
                bssid, ch, enc, cipher, pwr, essid);
            if (n >= 5 && network_count < MAX_NETWORKS) {
                if (strstr(line, "WPS")) strcpy(wps, "Yes");
                strncpy(networks[network_count].bssid, bssid, sizeof(networks[network_count].bssid)-1);
                strncpy(networks[network_count].channel, ch, sizeof(networks[network_count].channel)-1);
                strncpy(networks[network_count].enc, enc, sizeof(networks[network_count].enc)-1);
                strncpy(networks[network_count].cipher, cipher, sizeof(networks[network_count].cipher)-1);
                strncpy(networks[network_count].ssid, essid, sizeof(networks[network_count].ssid)-1);
                strncpy(networks[network_count].signal, pwr, sizeof(networks[network_count].signal)-1);
                strncpy(networks[network_count].wps, wps, sizeof(networks[network_count].wps)-1);
                network_count++;
            }
        }
    }
    fclose(fp);
}

// ==== Interface List ====
void list_monitor_interfaces(GtkComboBoxText *combo) {
    FILE *fp = popen("iw dev | grep Interface | awk '{print $2}'", "r");
    char buf[32];
    gtk_combo_box_text_remove_all(combo);
    while (fgets(buf, sizeof(buf), fp)) {
        buf[strcspn(buf, "\n")] = 0;
        // Check if in monitor mode
        char cmd[128], mode[32] = "";
        snprintf(cmd, sizeof(cmd), "iw dev %s info | grep type | awk '{print $2}'", buf);
        FILE *fp2 = popen(cmd, "r");
        if (fp2 && fgets(mode, sizeof(mode), fp2)) {
            mode[strcspn(mode, "\n")] = 0;
            if (strcmp(mode, "monitor") == 0)
                gtk_combo_box_text_append(combo, NULL, buf);
        }
        if (fp2) pclose(fp2);
    }
    pclose(fp);
}

// ==== Network Scan Thread ====
void* scan_networks_thread(void* arg) {
    scanning = true;
    char csv_file[] = "/tmp/audit.csv";
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "airodump-ng --wps --output-format csv -w /tmp/audit %s > /dev/null 2>&1", monitor_iface);
    system("rm -f /tmp/audit.csv /tmp/audit-01.csv");
    set_notification_threadsafe("Scanning WiFi networks...");

    // Run in the background for GUI responsiveness
    char bgcmd[300];
    snprintf(bgcmd, sizeof(bgcmd), "%s &", cmd);
    system(bgcmd);

    sleep(3); // Let airodump-ng start
    while (scanning) {
        if (access("/tmp/audit-01.csv", F_OK) == 0) {
            parse_airodump_csv("/tmp/audit-01.csv");
            g_idle_add(update_networks_gui, NULL);
        }
        sleep(2);
    }
    system("pkill -f \"airodump-ng --wps\"");
    set_notification_threadsafe("Stopped scanning.");
    return NULL;
}

// ==== Handshake Capture Thread ====
void* capture_handshake_thread(void* arg) {
    capturing_handshake = true;
    char cap_cmd[512];
    char deauth_cmd[256];
    char capfile[128];
    snprintf(capfile, sizeof(capfile), "/tmp/handshake_%s_%s", cap_bssid, cap_channel);
    snprintf(cap_cmd, sizeof(cap_cmd),
        "airodump-ng --bssid %s -c %s -w %s --output-format pcap,csv %s > /dev/null 2>&1 &",
        cap_bssid, cap_channel, capfile, monitor_iface);
    set_notification_threadsafe("Capturing handshake...");
    system(cap_cmd);
    sleep(2);
    snprintf(deauth_cmd, sizeof(deauth_cmd),
        "aireplay-ng --deauth 20 -a %s %s > /dev/null 2>&1", cap_bssid, monitor_iface);
    set_notification_threadsafe("Deauthenticating clients...");
    system(deauth_cmd);
    int max_time = 30, t = 0;
    while (capturing_handshake && t < max_time) {
        sleep(2);
        t+=2;
        char check_cmd[256];
        snprintf(check_cmd, sizeof(check_cmd), "aircrack-ng %s-01.cap | grep '1 handshake' > /dev/null", capfile);
        if (system(check_cmd) == 0) {
            set_notification_threadsafe("Handshake captured!");
            if (handshake_count < MAX_HANDSHAKES) {
                handshake_t h;
                strncpy(h.filename, capfile, sizeof(h.filename)-1);
                strncpy(h.bssid, cap_bssid, sizeof(h.bssid)-1);
                strncpy(h.channel, cap_channel, sizeof(h.channel)-1);
                h.ssid[0] = 0;
                for (int i = 0; i < network_count; ++i) {
                    if (strcmp(networks[i].bssid, cap_bssid) == 0) {
                        strncpy(h.ssid, networks[i].ssid, sizeof(h.ssid)-1);
                        break;
                    }
                }
                handshakes[handshake_count++] = h;
                handshake_add_data_t *d = malloc(sizeof(handshake_add_data_t));
                d->h = h;
                g_idle_add(add_handshake_gui, d);
            }
            break;
        }
    }
    capturing_handshake = false;
    system("pkill -f \"airodump-ng --bssid\"");
    set_notification_threadsafe("Handshake capture stopped.");
    return NULL;
}

// ==== Stop Handshake ====
void stop_capture() {
    capturing_handshake = false;
    system("pkill -f \"airodump-ng --bssid\"");
}

// ==== GUI Handlers ====
void iface_changed(GtkComboBoxText *combo, gpointer user_data) {
    strcpy(monitor_iface, gtk_combo_box_text_get_active_text(combo));
    set_notification_threadsafe("Monitor interface selected.");
}
void start_scan(GtkButton *btn, gpointer user_data) {
    if (scanning) return;
    pthread_create(&scan_thread, NULL, scan_networks_thread, NULL);
}
void stop_scan(GtkButton *btn, gpointer user_data) {
    scanning = false;
    pthread_join(scan_thread, NULL);
}
void start_capture(GtkButton *btn, gpointer user_data) {
    if (!scanning || capturing_handshake) return;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
    GtkTreeModel *model;
    GtkTreeIter iter;
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gchar *bssid, *ch;
        gtk_tree_model_get(model, &iter, 1, &bssid, 4, &ch, -1);
        strncpy(cap_bssid, bssid, sizeof(cap_bssid)-1);
        strncpy(cap_channel, ch, sizeof(cap_channel)-1);
        g_free(bssid); g_free(ch);
        capturing_handshake = true;
        pthread_create(&capture_thread, NULL, capture_handshake_thread, NULL);
    }
}
void stop_capture_btn(GtkButton *btn, gpointer user_data) {
    stop_capture();
}
void deauth_all(GtkButton *btn, gpointer user_data) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
    GtkTreeModel *model;
    GtkTreeIter iter;
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gchar *bssid;
        gtk_tree_model_get(model, &iter, 1, &bssid, -1);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "aireplay-ng --deauth 20 -a %s %s > /dev/null 2>&1", bssid, monitor_iface);
        set_notification_threadsafe("Deauthenticating all clients...");
        system(cmd);
        set_notification_threadsafe("Deauth sent.");
        g_free(bssid);
    }
}
void download_handshake(GtkButton *btn, gpointer user_data) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(handshake_treeview));
    GtkTreeModel *model;
    GtkTreeIter iter;
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gchar *file, *ssid;
        gtk_tree_model_get(model, &iter, 3, &file, 0, &ssid, -1);
        GtkWidget *dialog = gtk_file_chooser_dialog_new(
            "Save Handshake", GTK_WINDOW(main_window),
            GTK_FILE_CHOOSER_ACTION_SAVE,
            "_Cancel", GTK_RESPONSE_CANCEL,
            "_Save", GTK_RESPONSE_ACCEPT, NULL);
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), ssid);
        if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
            char *dest = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
            char srcfile[256];
            snprintf(srcfile, sizeof(srcfile), "%s-01.cap", file);
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "cp %s \"%s.cap\"", srcfile, dest);
            system(cmd);
            set_notification_threadsafe("Handshake downloaded.");
            g_free(dest);
        }
        gtk_widget_destroy(dialog);
        g_free(file); g_free(ssid);
    }
}

// ==== Build Main Tab ====
GtkWidget* build_main_tab() {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    GtkWidget *hbox_iface = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *iface_lbl = gtk_label_new("Monitor Interface:");
    iface_combo = gtk_combo_box_text_new();
    list_monitor_interfaces(GTK_COMBO_BOX_TEXT(iface_combo));
    g_signal_connect(iface_combo, "changed", G_CALLBACK(iface_changed), NULL);
    gtk_box_pack_start(GTK_BOX(hbox_iface), iface_lbl, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(hbox_iface), iface_combo, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), hbox_iface, FALSE, FALSE, 2);

    GtkWidget *hbox_btn = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *btn_scan = gtk_button_new_with_label("Start Scan");
    GtkWidget *btn_stop = gtk_button_new_with_label("Stop Scan");
    GtkWidget *btn_handshake = gtk_button_new_with_label("Start Handshake Capture");
    GtkWidget *btn_stopcap = gtk_button_new_with_label("Stop Capture");
    GtkWidget *btn_deauth = gtk_button_new_with_label("Deauth All Clients");
    gtk_box_pack_start(GTK_BOX(hbox_btn), btn_scan, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(hbox_btn), btn_stop, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(hbox_btn), btn_handshake, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(hbox_btn), btn_stopcap, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(hbox_btn), btn_deauth, FALSE, FALSE, 2);
    g_signal_connect(btn_scan, "clicked", G_CALLBACK(start_scan), NULL);
    g_signal_connect(btn_stop, "clicked", G_CALLBACK(stop_scan), NULL);
    g_signal_connect(btn_handshake, "clicked", G_CALLBACK(start_capture), NULL);
    g_signal_connect(btn_stopcap, "clicked", G_CALLBACK(stop_capture_btn), NULL);
    g_signal_connect(btn_deauth, "clicked", G_CALLBACK(deauth_all), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), hbox_btn, FALSE, FALSE, 2);

    store = gtk_list_store_new(6, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    treeview = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *col;
    const char *headers[] = {"SSID", "BSSID", "Security", "WPS", "Channel", "Signal"};
    for (int i = 0; i < 6; ++i) {
        if (i == 5) {
            renderer = gtk_cell_renderer_pixbuf_new();
            col = gtk_tree_view_column_new_with_attributes(headers[i], renderer, "icon-name", i, NULL);
        } else {
            renderer = gtk_cell_renderer_text_new();
            col = gtk_tree_view_column_new_with_attributes(headers[i], renderer, "text", i, NULL);
        }
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);
    }
    gtk_box_pack_start(GTK_BOX(vbox), treeview, TRUE, TRUE, 2);

    GtkWidget *notif_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
    GtkWidget *bell = gtk_image_new_from_icon_name("dialog-information", GTK_ICON_SIZE_DIALOG);
    notif_label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(notif_hbox), bell, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(notif_hbox), notif_label, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), notif_hbox, FALSE, FALSE, 2);

    return vbox;
}

// ==== Build Handshake Tab ====
GtkWidget* build_handshake_tab() {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    handshake_store = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    handshake_treeview = gtk_tree_view_new_with_model(GTK_TREE_MODEL(handshake_store));
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *col;
    const char *headers[] = {"SSID", "BSSID", "Channel", "File"};
    for (int i = 0; i < 4; ++i) {
        renderer = gtk_cell_renderer_text_new();
        col = gtk_tree_view_column_new_with_attributes(headers[i], renderer, "text", i, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(handshake_treeview), col);
    }
    gtk_box_pack_start(GTK_BOX(vbox), handshake_treeview, TRUE, TRUE, 2);

    GtkWidget *btn_dl = gtk_button_new_with_label("Download Handshake");
    gtk_box_pack_start(GTK_BOX(vbox), btn_dl, FALSE, FALSE, 2);
    g_signal_connect(btn_dl, "clicked", G_CALLBACK(download_handshake), NULL);

    return vbox;
}

// ==== Main ====
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "WiFi Auditor (Educational, CEH)");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 950, 600);
    g_signal_connect(main_window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *notebook = gtk_notebook_new();
    GtkWidget *main_tab = build_main_tab();
    GtkWidget *handshake_tab = build_handshake_tab();

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), main_tab, gtk_label_new("Main"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), handshake_tab, gtk_label_new("Handshakes"));

    gtk_container_add(GTK_CONTAINER(main_window), notebook);
    gtk_widget_show_all(main_window);

    gtk_main();
    scanning = false;
    capturing_handshake = false;
    return 0;
}
