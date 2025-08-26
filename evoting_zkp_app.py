# --- START OF FILE: evoting_zkp_app_ux.py ---
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox, simpledialog
import random
import os
import datetime
import hashlib

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx

# ---- Robust crypto imports: try PyCryptodome ('Crypto'), else PyCryptodomeX ('Cryptodome') ----
try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Random import get_random_bytes as _get_random_bytes
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES as _AES
    from Cryptodome.Random import get_random_bytes as _get_random_bytes


class AESCipher:
    """AES-GCM symmetric encryption with integrity (nonce(12B)+tag(16B)+ciphertext)."""
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16/24/32 bytes long")
        self.key = key

    def encrypt(self, plaintext: str) -> bytes:
        nonce = _get_random_bytes(12)
        cipher = _AES.new(self.key, _AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return nonce + tag + ciphertext

    def decrypt(self, data: bytes) -> str:
        try:
            nonce = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            cipher = _AES.new(self.key, _AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")


class Voter:
    """Voter model: id, name, and whether already voted."""
    def __init__(self, voter_id, name):
        self.voter_id = voter_id
        self.name = name
        self.has_voted = False


class VotingCenter:
    """Holds voters for a single center."""
    def __init__(self, center_name):
        self.center_name = center_name
        self.voters = {}

    def add_voter(self, voter: Voter):
        self.voters[voter.voter_id] = voter

    def get_voter(self, voter_id):
        return self.voters.get(voter_id, None)

    def count_voted(self):
        return sum(1 for v in self.voters.values() if v.has_voted)


class ZKPWindow(tk.Toplevel):
    """
    Zero Knowledge Proof demo (Graph Isomorphism).
    UX enhancements: color-coded graphs, progress bar, and live status text.
    Calls back with (is_success: bool, success_rate: float).
    """
    LEFT_NODE_COLOR = "#4e79a7"   # blue
    RIGHT_NODE_COLOR = "#f28e2b"  # orange
    EDGE_COLOR = "#9aa5b1"

    def __init__(self, parent, on_result_callback=None, total_trials=20):
        super().__init__(parent)
        self.title("Zero Knowledge Proof - Graph Isomorphism")
        self.geometry("960x640")

        self.on_result_callback = on_result_callback
        self.total_trials = total_trials

        # Graphs: G1 (K5), G2 iso(G1), G3 non-iso
        self.G1 = nx.complete_graph(5)
        self.G2 = nx.relabel_nodes(self.G1, {i: (i + 1) % 5 for i in self.G1.nodes})
        self.G3 = nx.cycle_graph(5)

        # Randomly decide if right graph is isomorphic or not
        self.isomorphism_random = random.choice([True, False])
        self.success_count = 0

        self._create_widgets()
        self._draw_graphs()

    def _create_widgets(self):
        header = tk.Label(
            self, text="Prover/Verifier Interactive ZKP (GI)",
            font=("Helvetica", 16, "bold")
        )
        header.grid(row=0, column=0, columnspan=2, pady=(10, 0))

        # Better labels for clarity
        tk.Label(self, text="Public Graph (G1)", font=("Arial", 12, "bold"), fg=self.LEFT_NODE_COLOR) \
            .grid(row=1, column=0, padx=10, pady=5)
        tk.Label(self, text="Challenge Graph (G2/G3)", font=("Arial", 12, "bold"), fg=self.RIGHT_NODE_COLOR) \
            .grid(row=1, column=1, padx=10, pady=5)

        self.graph_frame1 = tk.Frame(self, width=440, height=360, bg="white")
        self.graph_frame1.grid(row=2, column=0, padx=12, pady=8, sticky="nsew")
        self.graph_frame2 = tk.Frame(self, width=440, height=360, bg="white")
        self.graph_frame2.grid(row=2, column=1, padx=12, pady=8, sticky="nsew")

        # grid stretch
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Controls
        controls = tk.Frame(self)
        controls.grid(row=3, column=0, columnspan=2, pady=(6, 2))

        self.run_btn = tk.Button(
            controls, text="Run Protocol", bg="#3498DB", fg="white",
            font=("Arial", 11, "bold"), command=self.run_protocol
        )
        self.run_btn.pack(side=tk.LEFT, padx=6)

        self.progress = ttk.Progressbar(controls, orient="horizontal", mode="determinate",
                                        maximum=self.total_trials, length=300)
        self.progress.pack(side=tk.LEFT, padx=10)

        self.status_var = tk.StringVar(value="Ready")
        self.status_lbl = tk.Label(self, textvariable=self.status_var, font=("Arial", 11))
        self.status_lbl.grid(row=4, column=0, columnspan=2, pady=(4, 10))

        self.result_lbl = tk.Label(self, text="", font=("Arial", 12, "bold"))
        self.result_lbl.grid(row=5, column=0, columnspan=2, pady=(0, 10))

    def _draw_graphs(self):
        self._draw_single_graph(self.G1, self.graph_frame1, self.LEFT_NODE_COLOR)
        if self.isomorphism_random:
            self._draw_single_graph(self.G2, self.graph_frame2, self.RIGHT_NODE_COLOR)
        else:
            self._draw_single_graph(self.G3, self.graph_frame2, self.RIGHT_NODE_COLOR)

    def _draw_single_graph(self, graph, container, node_color):
        for w in container.winfo_children():
            w.destroy()
        fig, ax = plt.subplots(figsize=(4.6, 3.8))
        pos = nx.spring_layout(graph, seed=42)
        nx.draw(
            graph, pos=pos, with_labels=True, ax=ax,
            node_color=node_color, edge_color=self.EDGE_COLOR,
            node_size=600, font_size=10
        )
        fig.tight_layout()
        canvas_widget = FigureCanvasTkAgg(fig, master=container)
        canvas_widget.draw()
        canvas_widget.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close(fig)

    def single_trial(self):
        """One interactive GI round. Returns True on success."""
        # Commit: permute G1
        random_permutation = list(self.G1.nodes)
        random.shuffle(random_permutation)
        perm_mapping = {old: new for old, new in zip(self.G1.nodes, random_permutation)}
        G_permuted = nx.relabel_nodes(self.G1, perm_mapping)

        # Challenge: 1 -> compare to G1, 2 -> compare to (G2 or G3)
        verifier_choice = random.choice([1, 2])
        G_chosen = self.G1 if verifier_choice == 1 else (self.G2 if self.isomorphism_random else self.G3)

        if verifier_choice == 1:
            response_mapping = perm_mapping
        else:
            # If chosen graph is truly iso to G1, we can compose mappings.
            isomorphism_mapping = {i: (i + 1) % 5 for i in self.G1.nodes}  # G1 -> G2 mapping
            inverse_iso = {v: k for k, v in isomorphism_mapping.items()}
            response_mapping = {}
            for k in self.G1.nodes:
                original_node_in_G1 = inverse_iso.get(k, None)
                if original_node_in_G1 is None:
                    return False  # Not isomorphic case (G3) → likely fail
                response_mapping[k] = perm_mapping[original_node_in_G1]

        G_chosen_relabel = nx.relabel_nodes(G_chosen, response_mapping, copy=True)
        return nx.is_isomorphic(G_chosen_relabel, G_permuted)

    def run_protocol(self):
        # UI prep
        self.run_btn.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.status_var.set(f"Running {self.total_trials} trials...")
        self.result_lbl.config(text="")
        self.update_idletasks()

        self.success_count = 0
        for i in range(1, self.total_trials + 1):
            if self.single_trial():
                self.success_count += 1
            self.progress["value"] = i
            rate = (self.success_count / i) * 100.0
            self.status_var.set(f"Trial {i}/{self.total_trials} • Success so far: {rate:.1f}%")
            self.update_idletasks()

        success_rate = (self.success_count / self.total_trials) * 100.0
        correct_msg = "The graphs are isomorphic." if self.isomorphism_random else "The graphs are NOT isomorphic."

        if success_rate >= 90:
            verdict = "Verifier concludes they are isomorphic (high success)."
            is_success = True
            self.result_lbl.config(text="ACCESS GRANTED", fg="#1E8449")  # green
        else:
            verdict = "Verifier concludes they are NOT isomorphic (low success)."
            is_success = False
            self.result_lbl.config(text="ACCESS DENIED", fg="#C0392B")   # red

        messagebox.showinfo(
            "ZKP Result",
            f"Accuracy: {success_rate:.2f}%\n{correct_msg}\n{verdict}"
        )

        if self.on_result_callback:
            self.on_result_callback(is_success, success_rate)
        self.destroy()


class EVotingApp:
    """E-voting demo with GI-ZKP gate and AES-GCM encrypted ballots. Now with nicer UI feedback."""
    def __init__(self, root):
        self.root = root
        self.root.title("Electronic Voting with Graph ZKP Demo")
        self.root.geometry("940x700")
        self.root.configure(bg="#B0C4DE")

        # Admin user (hash of "admin")
        self.users_db = {
            "admin": ("8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", "admin")
        }
        self.is_admin = False

        # AES key (demo only)
        self.shared_key = b"SixteenByteKey!!"
        self.aes_cipher = AESCipher(self.shared_key)

        # Ballot box (encrypted)
        self.encrypted_ballot_box = []

        # Voting centers
        self.centerA = VotingCenter("Center A")
        self.centerB = VotingCenter("Center B")
        self.centerC = VotingCenter("Center C")

        self.setup_demo_voters()
        self.setup_log_directory()
        self.build_gui()
        self.switch_to_voter_mode()

    def setup_demo_voters(self):
        NAMES = [
            "John", "Michael", "Sarah", "Jessica", "Chris", "Jennifer",
            "David", "Emily", "Robert", "Heather", "Linda", "Paul",
            "Daniel", "Ashley", "Kyle", "Natalie", "Ryan", "Sophia",
            "Andrew", "Caroline"
        ]
        for i in range(1, 11):
            self.centerA.add_voter(Voter(f"A{str(i).zfill(3)}", random.choice(NAMES)))
            self.centerB.add_voter(Voter(f"B{str(i).zfill(3)}", random.choice(NAMES)))
            self.centerC.add_voter(Voter(f"C{str(i).zfill(3)}", random.choice(NAMES)))

    def setup_log_directory(self):
        self.log_dir = "logs"
        os.makedirs(self.log_dir, exist_ok=True)
        self.audit_log_path = os.path.join(self.log_dir, "AuditLog.txt")

    def write_audit_log(self, action):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {action}\n"
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(entry)

    def build_gui(self):
        lbl_title = tk.Label(self.root, text="E-Voting System + Zero Knowledge Proof (GI)",
                             font=("Helvetica", 18, "bold"),
                             bg="#B0C4DE", fg="#2C3E50")
        lbl_title.pack(pady=10)

        # Voter screen
        self.frame_voter = tk.Frame(self.root, bg="#F0F8FF", bd=2, relief=tk.RIDGE)

        tk.Label(self.frame_voter, text="Enter Voter ID:", font=("Arial", 12),
                 bg="#F0F8FF", fg="#000").grid(row=0, column=0, padx=5, pady=10, sticky="e")

        self.voter_id_entry = tk.Entry(self.frame_voter, width=25)
        self.voter_id_entry.grid(row=0, column=1, padx=5, pady=10)

        self.zkp_button = tk.Button(
            self.frame_voter, text="Prove Identity (ZKP)",
            bg="#3498DB", fg="white", font=("Arial", 11, "bold"),
            command=self.run_zkp_for_voter
        )
        self.zkp_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.vote_button_dem = tk.Button(
            self.frame_voter, text="Vote Democrat",
            bg="#2ECC71", fg="white", font=("Arial", 11, "bold"),
            command=lambda: self.submit_vote("D"), state=tk.DISABLED
        )
        self.vote_button_dem.grid(row=2, column=0, padx=5, pady=5)

        self.vote_button_rep = tk.Button(
            self.frame_voter, text="Vote Republican",
            bg="#E67E22", fg="white", font=("Arial", 11, "bold"),
            command=lambda: self.submit_vote("R"), state=tk.DISABLED
        )
        self.vote_button_rep.grid(row=2, column=1, padx=5, pady=5)

        self.btn_admin = tk.Button(
            self.frame_voter, text="Admin Access",
            bg="#8E44AD", fg="white", font=("Arial", 11, "bold"),
            command=self.admin_access_popup
        )
        self.btn_admin.grid(row=3, column=0, columnspan=2, pady=15)

        # Admin screen
        self.frame_admin = tk.Frame(self.root, bg="#F0F8FF", bd=2, relief=tk.RIDGE)

        self.back_to_voting_btn = tk.Button(
            self.frame_admin, text="Back to Voting",
            bg="#95A5A6", fg="white", font=("Arial", 11, "bold"),
            command=self.switch_to_voter_mode
        )
        self.back_to_voting_btn.grid(row=0, column=0, columnspan=2, pady=10)

        self.add_voter_button = tk.Button(
            self.frame_admin, text="Add Voter",
            bg="#3498DB", fg="white", font=("Arial", 11, "bold"),
            command=self.add_voter
        )
        self.add_voter_button.grid(row=1, column=0, columnspan=2, pady=5)

        self.tally_button = tk.Button(
            self.frame_admin, text="Show Final Results & Graph",
            bg="#27AE60", fg="white", font=("Arial", 11, "bold"),
            command=self.show_tally
        )
        self.tally_button.grid(row=2, column=0, columnspan=2, pady=5)

        self.save_button = tk.Button(
            self.frame_admin, text="Save Results to File",
            bg="#2980B9", fg="white", font=("Arial", 11, "bold"),
            command=self.save_results
        )
        self.save_button.grid(row=3, column=0, columnspan=2, pady=5)

        self.verify_button = tk.Button(
            self.frame_admin, text="Verify Results",
            bg="#8E44AD", fg="white", font=("Arial", 11, "bold"),
            command=self.verify_results
        )
        self.verify_button.grid(row=4, column=0, columnspan=2, pady=5)

        self.show_voters_button = tk.Button(
            self.frame_admin, text="Show Voters by Center",
            bg="#8E44AD", fg="white", font=("Arial", 11, "bold"),
            command=self.show_voters_by_center
        )
        self.show_voters_button.grid(row=5, column=0, columnspan=2, pady=5)

        # Log frame
        self.log_frame = tk.Frame(self.root, bg="#F0F8FF", bd=2, relief=tk.GROOVE)
        self.log_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        lbl_log = tk.Label(self.log_frame, text="Log Messages:",
                           font=("Arial", 10, "bold"),
                           bg="#F0F8FF", fg="#000")
        lbl_log.pack(anchor="nw")

        self.log_area = tk.Text(self.log_frame, height=10, state=tk.DISABLED,
                                wrap=tk.WORD, bg="#FAFAFA",
                                fg="#2C3E50", font=("Courier", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def switch_to_voter_mode(self):
        self.is_admin = False
        self.frame_admin.pack_forget()
        self.frame_voter.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        self.log_message("Switched to Voter Mode")

    def switch_to_admin_mode(self):
        self.is_admin = True
        self.frame_voter.pack_forget()
        self.frame_admin.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        self.log_message("Switched to Admin Mode")

    def log_message(self, msg):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.config(state=tk.DISABLED)
        self.log_area.see(tk.END)

    def admin_access_popup(self):
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Admin Login")
        self.login_window.geometry("300x200")
        self.login_window.configure(bg="#D6EAF8")

        tk.Label(self.login_window, text="Username:", bg="#D6EAF8").pack(pady=5)
        self.username_entry = tk.Entry(self.login_window)
        self.username_entry.pack()

        tk.Label(self.login_window, text="Password:", bg="#D6EAF8").pack(pady=5)
        self.password_entry = tk.Entry(self.login_window, show="*")
        self.password_entry.pack()

        login_btn = tk.Button(
            self.login_window, text="Login",
            bg="#5DADE2", fg="white",
            command=self.attempt_admin_login
        )
        login_btn.pack(pady=10)

        self.login_window.grab_set()
        self.login_window.focus_force()

    def attempt_admin_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if username in self.users_db:
            stored_hash, role = self.users_db[username]
            entered_hash = hashlib.sha256(password.encode()).hexdigest()
            if entered_hash == stored_hash and role == "admin":
                self.login_window.destroy()
                self.log_message("Admin login successful.")
                self.write_audit_log("Admin login successful.")
                self.switch_to_admin_mode()
                return

        messagebox.showerror("Login Failed", "Invalid admin credentials.")
        self.write_audit_log("Admin login attempt FAILED")

    def run_zkp_for_voter(self):
        voter_id = self.voter_id_entry.get().strip()
        if not voter_id:
            messagebox.showerror("Error", "Please enter a Voter ID.")
            return

        voter = self.find_voter(voter_id)
        if not voter:
            messagebox.showerror("Error", "Voter not found.")
            return

        if voter.has_voted:
            messagebox.showwarning("Already Voted", "This voter has already voted.")
            return

        # Live log for UX
        self.log_message(f"Running ZKP for voter {voter_id} (20 trials)...")
        self.write_audit_log(f"ZKP started for {voter_id}")

        def zkp_result_callback(is_success, success_rate):
            if is_success:
                self.log_message(f"ZKP succeeded for {voter_id} • {success_rate:.2f}% → Access granted")
                self.write_audit_log(f"ZKP success for {voter_id} ({success_rate:.2f}%)")
                messagebox.showinfo("ZKP", f"ZKP success for voter {voter_id} ({success_rate:.2f}%). You can vote now!")
                self.vote_button_dem.config(state=tk.NORMAL)
                self.vote_button_rep.config(state=tk.NORMAL)
            else:
                self.log_message(f"ZKP failed for {voter_id} • {success_rate:.2f}% → Access denied")
                self.write_audit_log(f"ZKP fail for {voter_id} ({success_rate:.2f}%)")
                messagebox.showerror("ZKP", f"ZKP failed for voter {voter_id} ({success_rate:.2f}%). Cannot vote.")

        ZKPWindow(self.root, on_result_callback=zkp_result_callback, total_trials=20)

    def find_voter(self, voter_id):
        for center in (self.centerA, self.centerB, self.centerC):
            voter = center.get_voter(voter_id)
            if voter:
                return voter
        return None

    def submit_vote(self, candidate):
        voter_id = self.voter_id_entry.get().strip()
        voter = self.find_voter(voter_id)
        if not voter:
            messagebox.showerror("Error", "Voter not found.")
            return

        if voter.has_voted:
            messagebox.showwarning("Already Voted", "This voter has already voted.")
            return

        try:
            voter.has_voted = True
            self.encrypted_ballot_box.append(self.aes_cipher.encrypt(candidate))
        except Exception as e:
            voter.has_voted = False
            messagebox.showerror("Encryption Error", f"Failed to encrypt vote: {e}")
            return

        msg = f"Voter {voter_id} has cast a vote (encrypted)."
        self.log_message(msg)
        self.write_audit_log(msg)

        self.vote_button_dem.config(state=tk.DISABLED)
        self.vote_button_rep.config(state=tk.DISABLED)

    def add_voter(self):
        if not self.is_admin:
            messagebox.showerror("Permission Denied", "Only admin can add voters.")
            return

        voter_id = simpledialog.askstring("Add Voter", "Enter Voter ID (e.g., A011):")
        voter_name = simpledialog.askstring("Add Voter", "Enter Voter Name:")
        if not voter_id or not voter_name:
            messagebox.showerror("Error", "Both Voter ID and Name are required!")
            return

        if self.find_voter(voter_id):
            messagebox.showerror("Error", f"Voter ID {voter_id} already exists!")
            return

        center_choice = simpledialog.askstring("Select Voting Center", "Enter Center (A, B, or C):")
        if not center_choice or center_choice.upper() not in ["A", "B", "C"]:
            messagebox.showerror("Error", "Invalid center selection! Please choose A, B, or C.")
            return

        new_voter = Voter(voter_id, voter_name)
        if center_choice.upper() == "A":
            self.centerA.add_voter(new_voter)
        elif center_choice.upper() == "B":
            self.centerB.add_voter(new_voter)
        elif center_choice.upper() == "C":
            self.centerC.add_voter(new_voter)

        msg = f"Added new voter: {voter_id} ({voter_name}) to Center {center_choice.upper()}"
        self.log_message(msg)
        self.write_audit_log(msg)

    def show_tally(self):
        if not self.is_admin:
            messagebox.showerror("Permission Denied", "Only admin can view the tally.")
            return

        try:
            dem_count = sum(1 for vote in self.encrypted_ballot_box if self.aes_cipher.decrypt(vote) == "D")
            rep_count = sum(1 for vote in self.encrypted_ballot_box if self.aes_cipher.decrypt(vote) == "R")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to tally votes: {e}")
            return

        total_votes = dem_count + rep_count
        if total_votes == 0:
            messagebox.showinfo("Results", "No votes have been cast yet.")
            return

        dem_percent = (dem_count / total_votes) * 100
        rep_percent = (rep_count / total_votes) * 100

        self.write_audit_log("Admin viewed the final tally.")

        result_window = tk.Toplevel(self.root)
        result_window.title("Election Results")
        result_window.geometry("600x500")
        result_window.configure(bg="#EBF5FB")

        lbl_msg = tk.Label(result_window,
                           text=f"Democrats: {dem_count} ({dem_percent:.2f}%)\n"
                                f"Republicans: {rep_count} ({rep_percent:.2f}%)",
                           font=("Arial", 14),
                           bg="#EBF5FB", fg="#2C3E50")
        lbl_msg.pack(pady=10)

        fig, ax = plt.subplots(figsize=(5, 3))
        labels = ['Democrats', 'Republicans']
        sizes = [dem_count, rep_count]
        colors = ['#1f77b4', '#ff7f0e']
        explode = (0.1, 0)
        ax.pie(sizes, explode=explode, labels=labels, colors=colors,
               autopct='%1.1f%%', shadow=True, startangle=140)
        ax.axis('equal')
        plt.title("Voting Results", fontsize=14)
        plt.subplots_adjust(top=0.85)

        canvas = FigureCanvasTkAgg(fig, master=result_window)
        canvas.get_tk_widget().pack()
        canvas.draw()
        plt.close(fig)

    def save_results(self):
        if not self.is_admin:
            messagebox.showerror("Permission Denied", "Only admin can save results.")
            return

        try:
            dem_count = sum(1 for vote in self.encrypted_ballot_box if self.aes_cipher.decrypt(vote) == "D")
            rep_count = sum(1 for vote in self.encrypted_ballot_box if self.aes_cipher.decrypt(vote) == "R")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to read votes: {e}")
            return

        total_votes = dem_count + rep_count
        if total_votes == 0:
            messagebox.showerror("Error", "No votes to save.")
            return

        voters_center_a = self.centerA.count_voted()
        voters_center_b = self.centerB.count_voted()
        voters_center_c = self.centerC.count_voted()

        results_path = os.path.join(os.getcwd(), "voting_results.txt")
        with open(results_path, "w", encoding="utf-8") as file:
            file.write("Election Results\n")
            file.write("================\n")
            file.write(f"Democrats: {dem_count} votes\n")
            file.write(f"Republicans: {rep_count} votes\n")
            file.write("\n--- Voters by Center ---\n")
            file.write(f"Center A: {voters_center_a} votes\n")
            file.write(f"Center B: {voters_center_b} votes\n")
            file.write(f"Center C: {voters_center_c} votes\n")
            file.write(f"Total Votes: {total_votes}\n")
            file.write("\n--- Election Summary ---\n")
            file.write(f"Democrats: {dem_count} ({(dem_count / total_votes) * 100:.2f}%)\n")
            file.write(f"Republicans: {rep_count} ({(rep_count / total_votes) * 100:.2f}%)\n")

        messagebox.showinfo("Saved", f"Results saved to {results_path}")
        self.write_audit_log(f"Admin saved results to file: {results_path}")

    def verify_results(self):
        if not self.is_admin:
            messagebox.showerror("Permission Denied", "Only admin can verify results.")
            return

        if not self.encrypted_ballot_box:
            messagebox.showinfo("Verification", "No votes to verify.")
            return

        verification_log = "Encrypted Votes Log:\n"
        for i, vote in enumerate(self.encrypted_ballot_box, start=1):
            verification_log += f"Vote {i}: {vote.hex()}\n"

        results_path = os.path.join(os.getcwd(), "verification_log.txt")
        with open(results_path, "w", encoding="utf-8") as file:
            file.write(verification_log)

        messagebox.showinfo("Verification", f"Verification log saved to '{results_path}'.")
        self.write_audit_log(f"Admin verified results and saved log: {results_path}")

    def show_voters_by_center(self):
        if not self.is_admin:
            messagebox.showerror("Permission Denied", "Only admin can view the voters list.")
            return

        voters_window = tk.Toplevel(self.root)
        voters_window.title("Voters by Center")
        voters_window.geometry("500x400")
        voters_window.configure(bg="#F9F9F9")

        display_text = "=== Center A Voters ===\n"
        for v in self.centerA.voters.values():
            display_text += f"{v.voter_id} - {v.name} (Voted: {v.has_voted})\n"

        display_text += "\n=== Center B Voters ===\n"
        for v in self.centerB.voters.values():
            display_text += f"{v.voter_id} - {v.name} (Voted: {v.has_voted})\n"

        display_text += "\n=== Center C Voters ===\n"
        for v in self.centerC.voters.values():
            display_text += f"{v.voter_id} - {v.name} (Voted: {v.has_voted})\n"

        tk.Label(voters_window, text="Voters Listing:", font=("Arial", 12, "bold"), bg="#F9F9F9").pack(pady=5)
        text_box = tk.Text(voters_window, wrap=tk.WORD, font=("Arial", 10))
        text_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_box.insert(tk.END, display_text)
        text_box.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = EVotingApp(root)
    root.mainloop()
# --- END OF FILE ---
