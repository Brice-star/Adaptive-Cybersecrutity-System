#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import random
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel, QLineEdit, QComboBox,
    QGroupBox, QMessageBox, QDialog, QDialogButtonBox, QFormLayout, QCheckBox,
    QTextEdit, QTabWidget, QHeaderView, QAction, QFileDialog, QStatusBar
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor
import datetime
import pyqtgraph as pg

# ------------------- Variable d'adaptation ------------------
adaptation_decision = {
    "niveau": "alerte",
    "message": "",
    "suggestions": []
}
# Pour test, décommente un des blocs suivants
# adaptation_decision = {
#     "niveau": "blocage",
#     "message": "Surcharge cognitive critique : accès bloqué. Un superviseur a été notifié.",
#     "suggestions": []
# }
# ------------------------------------------------------------

class AlertDialog(QDialog):
    def __init__(self, message, suggestions, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Alerte cognitive")
        self.setModal(True)
        layout = QVBoxLayout()
        main_message = (
            "<b>Votre état cognitif semble momentanément moins optimal.</b><br><br>"
            "Nous vous recommandons de prendre une courte pause afin de préserver</b><br><br>"
            " votre attention et votre bien-être.<br>"
        )
        layout.addWidget(QLabel(main_message))
        if suggestions:
            sugg = QLabel("Suggestions :<br>" + "<br>".join(f"- {s}" for s in suggestions))
            sugg.setWordWrap(True)
            layout.addWidget(sugg)
        btn = QPushButton("J'ai lu / Fermer l’alerte")
        btn.setDefault(True)
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)
        self.setLayout(layout)
        self.setFixedWidth(390)
        self.setStyleSheet("""
           

            QPushButton {
                background-color: #B8860B;
                color: white;
                font-weight: bold;
                border-radius: 4px;
                padding: 8px 16px;
            }
        """)

class BlockActionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Blocage de sécurité")
        self.setModal(True)
        layout = QVBoxLayout()
        label = QLabel(
            "<b>Votre état cognitif est jugé critique.</b><br><br>"
            "Vous ne pouvez pas effectuer d'action pour l'instant.<br>"
            "<i>Veuillez contacter votre responsable.</i>"
        )
        label.setWordWrap(True)
        layout.addWidget(label)
        btn = QPushButton("Fermer")
        btn.setDefault(True)
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)
        self.setLayout(layout)
        self.setFixedWidth(390)
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
                border: 2px solid #d0d0d0;
                border-radius: 8px;
            }
            QPushButton {
                background-color: red;
                color: white;
                font-weight: bold;
                border-radius: 4px;
                padding: 8px 16px;
            }
        """)

class DoubleConfirmDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirmation requise")
        self.setModal(True)
        layout = QVBoxLayout()
        label = QLabel("Veuillez confirmer pour poursuivre cette action critique.")
        layout.addWidget(label)
        btns = QDialogButtonBox(QDialogButtonBox.Yes | QDialogButtonBox.No)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        self.setLayout(layout)
        self.setFixedWidth(350)

class RuleDialog(QDialog):
    def __init__(self, parent=None, rule_data=None):
        super().__init__(parent)
        self.rule_data = rule_data
        self.setWindowTitle("Ajouter/Modifier une règle")
        self.setModal(True)
        self.resize(400, 300)
        self.init_ui()
        if rule_data:
            self.load_rule_data()
    def init_ui(self):
        layout = QFormLayout()
        self.name_edit = QLineEdit()
        layout.addRow("Nom:", self.name_edit)
        self.action_combo = QComboBox()
        self.action_combo.addItems(["ACCEPT", "DROP", "REJECT"])
        layout.addRow("Action:", self.action_combo)
        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["INPUT", "OUTPUT", "FORWARD"])
        layout.addRow("Direction:", self.direction_combo)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "ICMP", "ALL"])
        layout.addRow("Protocole:", self.protocol_combo)
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("192.168.1.0/24 ou any")
        layout.addRow("Source:", self.source_edit)
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("192.168.1.100 ou any")
        layout.addRow("Destination:", self.dest_edit)
        self.sport_edit = QLineEdit()
        self.sport_edit.setPlaceholderText("1024-65535 ou any")
        layout.addRow("Port source:", self.sport_edit)
        self.dport_edit = QLineEdit()
        self.dport_edit.setPlaceholderText("80,443 ou any")
        layout.addRow("Port destination:", self.dport_edit)
        self.active_check = QCheckBox()
        self.active_check.setChecked(True)
        layout.addRow("Actif:", self.active_check)
        self.desc_edit = QTextEdit()
        self.desc_edit.setMaximumHeight(60)
        layout.addRow("Description:", self.desc_edit)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        self.setLayout(layout)
    def load_rule_data(self):
        if not self.rule_data:
            return
        self.name_edit.setText(self.rule_data.get('name', ''))
        self.action_combo.setCurrentText(self.rule_data.get('action', 'ACCEPT'))
        self.direction_combo.setCurrentText(self.rule_data.get('direction', 'INPUT'))
        self.protocol_combo.setCurrentText(self.rule_data.get('protocol', 'TCP'))
        self.source_edit.setText(self.rule_data.get('source', ''))
        self.dest_edit.setText(self.rule_data.get('destination', ''))
        self.sport_edit.setText(self.rule_data.get('sport', ''))
        self.dport_edit.setText(self.rule_data.get('dport', ''))
        self.active_check.setChecked(self.rule_data.get('active', True))
        self.desc_edit.setPlainText(self.rule_data.get('description', ''))
    def get_rule_data(self):
        return {
            'name': self.name_edit.text(),
            'action': self.action_combo.currentText(),
            'direction': self.direction_combo.currentText(),
            'protocol': self.protocol_combo.currentText(),
            'source': self.source_edit.text(),
            'destination': self.dest_edit.text(),
            'sport': self.sport_edit.text(),
            'dport': self.dport_edit.text(),
            'active': self.active_check.isChecked(),
            'description': self.desc_edit.toPlainText(),
            'created': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

class LogViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setup_timer()
    def init_ui(self):
        layout = QVBoxLayout()
        controls_layout = QHBoxLayout()
        self.auto_refresh_check = QCheckBox("Actualisation automatique")
        self.auto_refresh_check.setChecked(True)
        controls_layout.addWidget(self.auto_refresh_check)
        refresh_btn = QPushButton("Actualiser")
        refresh_btn.clicked.connect(self.refresh_logs)
        controls_layout.addWidget(refresh_btn)
        clear_btn = QPushButton("Effacer")
        clear_btn.clicked.connect(self.clear_logs)
        controls_layout.addWidget(clear_btn)
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 9))
        layout.addWidget(self.log_text)
        self.setLayout(layout)
    def setup_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.auto_refresh)
        self.timer.start(5000)
    def auto_refresh(self):
        if self.auto_refresh_check.isChecked():
            self.refresh_logs()
    def refresh_logs(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sample_logs = [
            f"[{timestamp}] DROP: 192.168.1.100:5432 -> 10.0.0.1:22 (SSH attempt blocked)",
            f"[{timestamp}] ACCEPT: 192.168.1.50:1024 -> 8.8.8.8:53 (DNS query)",
            f"[{timestamp}] DROP: 203.0.113.1:4444 -> 192.168.1.10:80 (Suspicious traffic)"
        ]
        current_text = self.log_text.toPlainText()
        new_text = current_text + "\n" + "\n".join(sample_logs)
        lines = new_text.split('\n')
        if len(lines) > 1000:
            lines = lines[-1000:]
            new_text = '\n'.join(lines)
        self.log_text.setPlainText(new_text)
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )
    def clear_logs(self):
        self.log_text.clear()

class StatsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setup_timer()
    def init_ui(self):
        layout = QGridLayout()
        stats_group = QGroupBox("Statistiques en temps réel")
        stats_layout = QGridLayout()
        self.packets_in_label = QLabel("Paquets entrants: 0")
        self.packets_out_label = QLabel("Paquets sortants: 0")
        self.packets_dropped_label = QLabel("Paquets bloqués: 0")
        self.connections_label = QLabel("Connexions actives: 0")
        stats_layout.addWidget(self.packets_in_label, 0, 0)
        stats_layout.addWidget(self.packets_out_label, 0, 1)
        stats_layout.addWidget(self.packets_dropped_label, 1, 0)
        stats_layout.addWidget(self.connections_label, 1, 1)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group, 0, 0, 1, 2)
        blocked_group = QGroupBox("Top IPs bloquées")
        blocked_layout = QVBoxLayout()
        self.blocked_table = QTableWidget(5, 2)
        self.blocked_table.setHorizontalHeaderLabels(["Adresse IP", "Tentatives"])
        self.blocked_table.horizontalHeader().setStretchLastSection(True)
        blocked_layout.addWidget(self.blocked_table)
        blocked_group.setLayout(blocked_layout)
        layout.addWidget(blocked_group, 1, 0)
        activity_group = QGroupBox("Activité réseau")
        activity_layout = QVBoxLayout()
        self.activity_text = QTextEdit()
        self.activity_text.setReadOnly(True)
        self.activity_text.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_text)
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group, 1, 1)
        self.setLayout(layout)
        self.update_stats()
    def setup_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(2000)
    def update_stats(self):
        self.packets_in_label.setText(f"Paquets entrants: {random.randint(1000, 9999)}")
        self.packets_out_label.setText(f"Paquets sortants: {random.randint(800, 5000)}")
        self.packets_dropped_label.setText(f"Paquets bloqués: {random.randint(10, 200)}")
        self.connections_label.setText(f"Connexions actives: {random.randint(5, 50)}")
        blocked_ips = [
            ("203.0.113.1", str(random.randint(5, 50))),
            ("198.51.100.10", str(random.randint(3, 30))),
            ("192.0.2.15", str(random.randint(2, 25))),
            ("10.0.0.1", str(random.randint(1, 15))),
            ("172.16.0.1", str(random.randint(1, 10)))
        ]
        for i, (ip, count) in enumerate(blocked_ips):
            self.blocked_table.setItem(i, 0, QTableWidgetItem(ip))
            self.blocked_table.setItem(i, 1, QTableWidgetItem(count))
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        activities = [
            f"[{timestamp}] Connexion SSH bloquée depuis 203.0.113.1",
            f"[{timestamp}] Scan de port détecté depuis 198.51.100.10",
            f"[{timestamp}] Tentative de connexion HTTP autorisée"
        ]
        current_text = self.activity_text.toPlainText()
        new_activity = random.choice(activities)
        new_text = current_text + "\n" + new_activity
        lines = new_text.split('\n')
        if len(lines) > 20:
            lines = lines[-20:]
            new_text = '\n'.join(lines)
        self.activity_text.setPlainText(new_text)
        self.activity_text.verticalScrollBar().setValue(
            self.activity_text.verticalScrollBar().maximum()
        )

class TrafficGraphWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        self.plot_widget = pg.PlotWidget(title="Trafic réseau (Entrants/Sortants, paquets/seconde)")
        self.plot_widget.setBackground('w')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setLabel('left', "Paquets / seconde", color='#444', size=12)
        self.plot_widget.setLabel('bottom', "Temps (s)", color='#444', size=12)
        self.plot_widget.addLegend()
        self.curve_in = self.plot_widget.plot(pen=pg.mkPen('g', width=2), name="Entrants")
        self.curve_out = self.plot_widget.plot(pen=pg.mkPen('b', width=2), name="Sortants")
        layout.addWidget(self.plot_widget)
        self.setLayout(layout)
        self.data_in = [random.randint(100, 300) for _ in range(60)]
        self.data_out = [random.randint(80, 250) for _ in range(60)]
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(1000)
        self.plot_widget.setYRange(0, 400)
        self.plot_widget.setXRange(0, 59)
        self.plot_widget.getAxis('bottom').setTicks([[(i, str(60-i)) for i in range(0, 61, 10)]])
        self.proxy = pg.SignalProxy(self.plot_widget.scene().sigMouseMoved, rateLimit=60, slot=self.mouse_moved)
        self.vLine = pg.InfiniteLine(angle=90, movable=False, pen=pg.mkPen('#aaa', width=1, style=3))
        self.plot_widget.addItem(self.vLine, ignoreBounds=True)
        self.label = pg.TextItem("", anchor=(0,1), color="#222")
        self.plot_widget.addItem(self.label)

    def update_graph(self):
        self.data_in = self.data_in[1:] + [random.randint(100, 300)]
        self.data_out = self.data_out[1:] + [random.randint(80, 250)]
        self.curve_in.setData(self.data_in, pen=pg.mkPen('g', width=2))
        self.curve_out.setData(self.data_out, pen=pg.mkPen('b', width=2))
        self.curve_in.setZValue(1)
        self.curve_out.setZValue(2)

    def mouse_moved(self, evt):
        pos = evt[0]
        vb = self.plot_widget.plotItem.vb
        if self.plot_widget.sceneBoundingRect().contains(pos):
            mouse_point = vb.mapSceneToView(pos)
            x = int(mouse_point.x())
            if 0 <= x < 60:
                y_in = self.data_in[x]
                y_out = self.data_out[x]
                self.label.setHtml(f'<span style="color:#006400;">Entrants: <b>{y_in}</b></span>  '
                                   f'<span style="color:#1E90FF;">Sortants: <b>{y_out}</b></span>')
                self.label.setPos(x, max(y_in, y_out)+15)
                self.vLine.setPos(x)

class FirewallAdmin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.rules = []
        self.alert_dialog = None
        self.alert_shown = False
        self.load_sample_rules()
        self.adaptation_banner = None
        self.init_ui()
        self.setup_status_bar()
        self.check_timer = QTimer()
        self.check_timer.timeout.connect(self.check_adaptation_alert)
        self.check_timer.start(500)

    def load_sample_rules(self):
        self.rules = [
            {
                'name': 'SSH Admin',
                'action': 'ACCEPT',
                'direction': 'INPUT',
                'protocol': 'TCP',
                'source': '192.168.1.0/24',
                'destination': 'any',
                'sport': 'any',
                'dport': '22',
                'active': True,
                'description': 'Autoriser SSH depuis le réseau local',
                'created': '2024-01-15 10:30:00'
            },
            {
                'name': 'Web Traffic',
                'action': 'ACCEPT',
                'direction': 'INPUT',
                'protocol': 'TCP',
                'source': 'any',
                'destination': 'any',
                'sport': 'any',
                'dport': '80,443',
                'active': True,
                'description': 'Autoriser le trafic web HTTP/HTTPS',
                'created': '2024-01-15 10:31:00'
            },
            {
                'name': 'Block Suspicious',
                'action': 'DROP',
                'direction': 'INPUT',
                'protocol': 'ALL',
                'source': '203.0.113.0/24',
                'destination': 'any',
                'sport': 'any',
                'dport': 'any',
                'active': True,
                'description': 'Bloquer réseau suspect',
                'created': '2024-01-15 10:32:00'
            }
        ]

    def init_ui(self):
        self.setWindowTitle("Administration de Pare-feu")
        self.setGeometry(100, 100, 1200, 800)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        self.adaptation_banner = self.create_adaptation_banner()
        main_layout.addWidget(self.adaptation_banner)
        self.tabs = QTabWidget()
        self.add_btn = None
        self.edit_btn = None
        self.delete_btn = None
        self.start_btn = None
        self.stop_btn = None
        self.reload_btn = None
        self.restore_action = None
        self.rules_table = None
        rules_widget = self.create_rules_tab()
        self.tabs.addTab(rules_widget, "Règles de pare-feu")
        self.log_viewer = LogViewer()
        self.tabs.addTab(self.log_viewer, "Journaux")
        self.stats_widget = StatsWidget()
        self.tabs.addTab(self.stats_widget, "Statistiques")
        main_layout.addWidget(self.tabs)
        self.graphic_group = QGroupBox("Trafic réseau en temps réel (dernière minute)")
        graph_layout = QVBoxLayout()
        self.traffic_graph = TrafficGraphWidget()
        graph_layout.addWidget(self.traffic_graph)
        self.graphic_group.setLayout(graph_layout)
        main_layout.addWidget(self.graphic_group)
        self.create_menu()
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QTableWidget {
                gridline-color: #d0d0d0;
                background-color: white;
                alternate-background-color: #f9f9f9;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """)
        self.apply_adaptation_decision()

    def update_rules_table(self):
        self.rules_table.setRowCount(len(self.rules))
        for i, rule in enumerate(self.rules):
            self.rules_table.setItem(i, 0, QTableWidgetItem(rule['name']))
            self.rules_table.setItem(i, 1, QTableWidgetItem(rule['action']))
            self.rules_table.setItem(i, 2, QTableWidgetItem(rule['direction']))
            self.rules_table.setItem(i, 3, QTableWidgetItem(rule['protocol']))
            self.rules_table.setItem(i, 4, QTableWidgetItem(rule['source']))
            self.rules_table.setItem(i, 5, QTableWidgetItem(rule['destination']))
            self.rules_table.setItem(i, 6, QTableWidgetItem(rule['dport']))
            status_item = QTableWidgetItem("✓" if rule['active'] else "✗")
            status_item.setTextAlignment(Qt.AlignCenter)
            if rule['active']:
                status_item.setBackground(QColor(200, 255, 200))
            else:
                status_item.setBackground(QColor(255, 200, 200))
            self.rules_table.setItem(i, 7, status_item)
            self.rules_table.setItem(i, 8, QTableWidgetItem(rule['description']))

    def add_rule(self):
        if not self.action_allowed("add"):
            return
        if not self.double_confirmation_if_needed("add"):
            return
        dialog = RuleDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            rule_data = dialog.get_rule_data()
            self.rules.append(rule_data)
            self.update_rules_table()
            self.status_bar.showMessage(f"Règle '{rule_data['name']}' ajoutée", 3000)

    def edit_rule(self):
        if not self.action_allowed("edit"):
            return
        if not self.double_confirmation_if_needed("edit"):
            return
        current_row = self.rules_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Attention", "Veuillez sélectionner une règle à modifier.")
            return
        rule_data = self.rules[current_row]
        dialog = RuleDialog(self, rule_data)
        if dialog.exec_() == QDialog.Accepted:
            updated_rule = dialog.get_rule_data()
            self.rules[current_row] = updated_rule
            self.update_rules_table()
            self.status_bar.showMessage(f"Règle '{updated_rule['name']}' modifiée", 3000)

    def delete_rule(self):
        if not self.action_allowed("delete"):
            return
        if not self.double_confirmation_if_needed("delete"):
            return
        current_row = self.rules_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Attention", "Veuillez sélectionner une règle à supprimer.")
            return
        rule_name = self.rules[current_row]['name']
        reply = QMessageBox.question(self, "Confirmation", 
                                   f"Êtes-vous sûr de vouloir supprimer la règle '{rule_name}' ?",
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            del self.rules[current_row]
            self.update_rules_table()
            self.status_bar.showMessage(f"Règle '{rule_name}' supprimée", 3000)

    def start_firewall(self):
        if not self.action_allowed("start"):
            return
        if not self.double_confirmation_if_needed("start"):
            return
        self.fw_status_label.setText("État: Actif")
        self.fw_status_label.setStyleSheet("color: green; font-weight: bold;")
        self.status_bar.showMessage("Pare-feu démarré", 3000)

    def stop_firewall(self):
        if not self.action_allowed("stop"):
            return
        if not self.double_confirmation_if_needed("stop"):
            return
        reply = QMessageBox.question(self, "Confirmation", 
                                     "Êtes-vous sûr de vouloir arrêter le pare-feu ?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.fw_status_label.setText("État: Inactif")
            self.fw_status_label.setStyleSheet("color: red; font-weight: bold;")
            self.status_bar.showMessage("Pare-feu arrêté", 3000)

    def reload_firewall(self):
        if not self.action_allowed("reload"):
            return
        if not self.double_confirmation_if_needed("reload"):
            return
        self.status_bar.showMessage("Rechargement des règles...", 2000)
        QTimer.singleShot(2000, lambda: self.status_bar.showMessage("Règles rechargées", 3000))

    def import_rules(self):
        if not self.action_allowed("import"):
            return
        if not self.double_confirmation_if_needed("import"):
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Importer règles", "", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    imported_rules = json.load(f)
                self.rules.extend(imported_rules)
                self.update_rules_table()
                self.status_bar.showMessage(f"{len(imported_rules)} règles importées", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de l'importation: {str(e)}")

    def export_rules(self):
        if not self.action_allowed("export"):
            return
        if not self.double_confirmation_if_needed("export"):
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Exporter règles", "firewall_rules.json", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.rules, f, indent=2, ensure_ascii=False)
                self.status_bar.showMessage("Règles exportées avec succès", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de l'exportation: {str(e)}")

    def backup_config(self):
        if not self.action_allowed("backup"):
            return
        if not self.double_confirmation_if_needed("backup"):
            return
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"firewall_backup_{timestamp}.json"
        try:
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(self.rules, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Succès", f"Configuration sauvegardée dans {backup_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde: {str(e)}")

    def restore_config(self):
        if not self.action_allowed("restore"):
            return
        if not self.double_confirmation_if_needed("restore"):
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Restaurer configuration", "", "JSON Files (*.json)")
        if file_path:
            reply = QMessageBox.question(self, "Confirmation", 
                                       "Cette action remplacera toutes les règles actuelles. Continuer ?",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        self.rules = json.load(f)
                    self.update_rules_table()
                    self.status_bar.showMessage("Configuration restaurée", 3000)
                except Exception as e:
                    QMessageBox.critical(self, "Erreur", f"Erreur lors de la restauration: {str(e)}")

    def action_allowed(self, action_name):
        global adaptation_decision
        niveau = adaptation_decision.get("niveau", "normal")
        if niveau == "blocage":
            dlg = BlockActionDialog(self)
            dlg.exec_()
            return False
        if niveau == "alerte":
            if (self.alert_dialog is not None) and self.alert_dialog.isVisible():
                self.alert_dialog.raise_()
                return False
        return True

    def double_confirmation_if_needed(self, action_name):
        global adaptation_decision
        niveau = adaptation_decision.get("niveau", "normal")
        if niveau == "restriction":
            dlg = DoubleConfirmDialog(self)
            if dlg.exec_() != QDialog.Accepted:
                return False
        return True

    def create_adaptation_banner(self):
        banner = QWidget()
        layout = QHBoxLayout()
        banner.setLayout(layout)
        self.adaptation_label = QLabel("")
        self.adaptation_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.suggestions_label = QLabel("")
        self.suggestions_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(self.adaptation_label)
        layout.addWidget(self.suggestions_label)
        banner.setStyleSheet("background:#F3F6FB; border-bottom:1px solid #A9A9A9;")
        return banner

    def apply_adaptation_decision(self):
        global adaptation_decision
        niveau = adaptation_decision.get("niveau", "normal")
        msg = adaptation_decision.get("message", "")
        suggestions = adaptation_decision.get("suggestions", [])
        color = {
            "normal": "background:#E9FBE9;color:#333;",
            "alerte": "background:#FFFDE7;color:#B8860B;",
            "restriction": "background:#FFF3E0;color:#F57C00;",
            "blocage": "background:#FFEBEE;color:#D32F2F;font-weight:bold;"
        }.get(niveau, "background:#F3F6FB;")
        self.adaptation_banner.setStyleSheet(color + "border-bottom:1px solid #A9A9A9;")
        self.adaptation_label.setText(f"Mode d'adaptation : <b>{niveau.upper()}</b>  {msg}")
        if niveau == "alerte" and suggestions:
            self.suggestions_label.setText("Suggestions : " + " | ".join(suggestions))
        else:
            self.suggestions_label.setText("")

    def check_adaptation_alert(self):
        global adaptation_decision
        niveau = adaptation_decision.get("niveau", "normal")
        suggestions = adaptation_decision.get("suggestions", [])
        if niveau == "alerte" and not self.alert_shown:
            self.alert_dialog = AlertDialog("", suggestions, self)
            self.alert_dialog.exec_()
            self.alert_shown = True
        elif niveau != "alerte":
            self.alert_shown = False
        self.apply_adaptation_decision()

    def set_critical_controls_enabled(self, enabled):
        if self.edit_btn:
            self.edit_btn.setEnabled(enabled)
        if self.delete_btn:
            self.delete_btn.setEnabled(enabled)
        if self.stop_btn:
            self.stop_btn.setEnabled(enabled)
        if self.rules_table:
            self.rules_table.setEnabled(enabled)
        if self.restore_action:
            self.restore_action.setEnabled(enabled)

    def create_rules_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        controls_layout = QHBoxLayout()
        self.add_btn = QPushButton("Ajouter règle")
        self.add_btn.clicked.connect(self.add_rule)
        controls_layout.addWidget(self.add_btn)
        self.edit_btn = QPushButton("Modifier")
        self.edit_btn.clicked.connect(self.edit_rule)
        controls_layout.addWidget(self.edit_btn)
        self.delete_btn = QPushButton("Supprimer")
        self.delete_btn.setStyleSheet("QPushButton { background-color: #f44336; }")
        self.delete_btn.clicked.connect(self.delete_rule)
        controls_layout.addWidget(self.delete_btn)
        controls_layout.addStretch()
        fw_controls_layout = QHBoxLayout()
        self.fw_status_label = QLabel("État: Actif")
        self.fw_status_label.setStyleSheet("color: green; font-weight: bold;")
        fw_controls_layout.addWidget(self.fw_status_label)
        self.start_btn = QPushButton("Démarrer")
        self.start_btn.clicked.connect(self.start_firewall)
        fw_controls_layout.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Arrêter")
        self.stop_btn.setStyleSheet("QPushButton { background-color: #ff9800; }")
        self.stop_btn.clicked.connect(self.stop_firewall)
        fw_controls_layout.addWidget(self.stop_btn)
        self.reload_btn = QPushButton("Recharger")
        self.reload_btn.clicked.connect(self.reload_firewall)
        fw_controls_layout.addWidget(self.reload_btn)
        controls_layout.addLayout(fw_controls_layout)
        layout.addLayout(controls_layout)
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(9)
        self.rules_table.setHorizontalHeaderLabels([
            "Nom", "Action", "Direction", "Protocole", "Source", 
            "Destination", "Port Dest", "Actif", "Description"
        ])
        header = self.rules_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.rules_table)
        widget.setLayout(layout)
        self.update_rules_table()
        return widget

    def create_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu('Fichier')
        import_action = QAction('Importer règles', self)
        import_action.triggered.connect(self.import_rules)
        file_menu.addAction(import_action)
        export_action = QAction('Exporter règles', self)
        export_action.triggered.connect(self.export_rules)
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        quit_action = QAction('Quitter', self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)
        config_menu = menubar.addMenu('Configuration')
        backup_action = QAction('Sauvegarder configuration', self)
        backup_action.triggered.connect(self.backup_config)
        config_menu.addAction(backup_action)
        self.restore_action = QAction('Restaurer configuration', self)
        self.restore_action.triggered.connect(self.restore_config)
        config_menu.addAction(self.restore_action)

    def setup_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Prêt")
        self.connection_label = QLabel("Connecté")
        self.connection_label.setStyleSheet("color: green;")
        self.status_bar.addPermanentWidget(self.connection_label)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Firewall Admin")
    app.setOrganizationName("FirewallTools")
    app.setStyle('Fusion')
    window = FirewallAdmin()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()