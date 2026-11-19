# Multi-Machine Two-Laptop Testing Playbook

**Document Role**: Multi-Machine End-to-End Validation Protocol  
**Scope**: Coordinated network policy testing between Laptop A (Auditor) and Laptop B (Consenting Target/Listener)  
**Environments Tested**: Local Area Network (Home Wi-Fi) and Cellular Hotspot (Mobile Tethering)  
**Safety Commitment**: Strictly targets consenting machines on private networks; includes immediate cleanup instructions for all listeners and firewall rules.  

---

## 1. Test Setup & Architecture

This protocol uses two laptops on the same physical Wi-Fi or tethered network:
- **Laptop A (Auditor)**: Runs `netpolicy` (interactive wizard or CLI) to dispatch network probes.
- **Laptop B (Target / Listener)**: Runs simple Python network listeners and temporary firewall rules to represent known ground truth.

```
┌─────────────────────────────────┐               ┌─────────────────────────────────┐
│     Laptop A (Auditor)          │  Wi-Fi / LAN  │     Laptop B (Listener)         │
│  IP: 192.168.1.100              ├──────────────►│  IP: 192.168.1.150              │
│                                 │               │                                 │
│  Runs: `netpolicy ports`        │               │  Port 8080: Python HTTP (OPEN)  │
│        Target: 192.168.1.150    │               │  Port 2222: Socket (OPEN)       │
│        Control Port: 8080       │               │  Port 9090: DROP Firewall Rule  │
│                                 │               │  Port 59999: No Listener (RST)  │
└─────────────────────────────────┘               └─────────────────────────────────┘
```

> [!IMPORTANT]
> **WSL2 NAT Warning for Laptop B**:  
> If you start listeners inside WSL2 on Laptop B, WSL2's virtual Hyper-V switch places them behind a private virtual subnet (e.g. `172.x.x.x`). Traffic arriving from Laptop A hits Laptop B's physical Wi-Fi IP and will be dropped unless Windows portproxy is configured.  
> **Recommended Solution**: Run listeners directly in Windows PowerShell on Laptop B to bind cleanly to all physical interfaces (`0.0.0.0`).

---

## 2. Step 1: Discover Laptop B's LAN IP Address

On Laptop B, determine the IPv4 address assigned by your Wi-Fi router or mobile hotspot:

### In Windows PowerShell (Laptop B):
```powershell
# Windows PowerShell (Laptop B) [VERIFIED command shape / UNVERIFIED on 2nd laptop]
(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*").IPAddress
```
*(Alternative: run `ipconfig` and look for the IPv4 Address under "Wireless LAN adapter Wi-Fi", e.g. `192.168.1.150`)*

### In Linux / WSL (Laptop B):
```bash
# Linux / WSL (Laptop B) [VERIFIED command shape / UNVERIFIED on 2nd laptop]
ip -br -4 addr show
```

*Record this IP address as `<LAPTOP_B_IP>` for use in subsequent steps.*

---

## 3. Step 2: Start Ground-Truth Listeners on Laptop B

On Laptop B, configure four distinct port states to validate classifier accuracy:

### Port 1: Open HTTP Service (Port 8080)
Start Python's built-in HTTP server listening on all network interfaces:
```powershell
# Windows PowerShell (Laptop B - Terminal 1) [UNVERIFIED on 2nd laptop]
python -m http.server 8080 --bind 0.0.0.0
```
*Expected: Serves directory listing; replies with HTTP 200 / TCP SYN-ACK.*

### Port 2: Open Custom TCP Service (Port 2222)
Start a minimal single-line Python TCP echo/connect listener:
```powershell
# Windows PowerShell (Laptop B - Terminal 2) [UNVERIFIED on 2nd laptop]
python -c "import socket; s=socket.socket(); s.bind(('0.0.0.0', 2222)); s.listen(5); print('TCP listener ready on 2222...'); [s.accept()[0].close() for _ in iter(int, 1)]"
```
*Expected: Accepts incoming TCP connections and closes them gracefully.*

### Port 3: Silently Filtered / Dropped Port (Port 9090)
Create a temporary firewall rule on Laptop B that silently discards incoming TCP packets to port `9090` without sending RST or ICMP packets.

#### On Windows (Run as Administrator in PowerShell on Laptop B):
```powershell
# Windows PowerShell as Administrator (Laptop B) [UNVERIFIED on 2nd laptop]
New-NetFirewallRule -DisplayName "NetPolicy-Test-Drop-9090" -Direction Inbound -LocalPort 9090 -Protocol TCP -Action Block
```

#### On Linux / WSL (Run as root on Laptop B):
```bash
# Linux / WSL as root (Laptop B) [UNVERIFIED on 2nd laptop]
sudo iptables -A INPUT -p tcp --dport 9090 -j DROP
```

### Port 4: Actively Closed Port (Port 59999)
Do **NOT** start any listener on port `59999`. Ensure the port remains closed so the operating system kernel returns an authentic TCP RST (`ECONNREFUSED`).

---

## 4. Step 3: Ground-Truth Validation Matrix

| Target Port | Physical State on Laptop B | Network Mechanism | Expected `netpolicy` Outcome | Expected Evidence |
|---|---|---|---|---|
| **`8080`** | Open | Python HTTP Server listening | `✓ OPEN` | `SYN-ACK in <50ms` |
| **`2222`** | Open | Python Socket Listener | `✓ OPEN` | `SYN-ACK in <50ms` |
| **`9090`** | Blocked | Inbound Firewall DROP rule | `✗ DROPPED` / `BLOCKED_DROP` | `0/3 replies (timeout)` |
| **`59999`** | Closed | No listener running on host | `✗ RESET` / `CLOSED_OR_RESET` | `TCP RST (Connection refused)` |

---

## 5. Step 4: Execute the Audit from Laptop A

From Laptop A, execute `netpolicy` targeting Laptop B's IP address:

### Non-Interactive CLI Execution:
```powershell
# Windows PowerShell (Laptop A) [UNVERIFIED on 2nd laptop]
netpolicy ports --target <LAPTOP_B_IP> --ports 8080,2222,9090,59999 --control-port 8080 --mode socket --runs 3
```

### Interactive Guided Wizard Execution:
1. On Laptop A, launch the wizard:
   ```powershell
   netpolicy
   ```
2. In `MAIN_MENU`, choose:  
   `2 See if something I use is being blocked (email, remote login, file sharing, websites)`
3. In `ASK_NETWORK_ENV`, choose:  
   `1 Home Wi-Fi / Personal Router`
4. In `TARGET`, choose:  
   `1 A server I own or manage (best results)`  
   Type Laptop B's IP address: `<LAPTOP_B_IP>`
5. In `PORTS`, choose:  
   `6 Custom list`  
   Type: `8080, 2222, 9090, 59999`
6. In `OPTIONS`, choose:  
   - Thoroughness: `Standard (5 checks, recommended)`
   - Method: `Standard (works on all computers)`
   - Capture: `No`
7. In `AUTHORIZE`, select:  
   `1 Yes, I am authorized`
8. In `REVIEW`, select:  
   `1 Run now`

---

## 6. Step 5: Two-Network Comparison Protocol (Wi-Fi vs Mobile Hotspot)

This test compares network filtering policies enforced by your home broadband Wi-Fi against a cellular carrier's mobile data hotspot (which frequently drops SMTP port 25 or transparently proxies port 80).

### Phase 1: Audit Home Wi-Fi (Laptop A on Home Network)
1. Ensure Laptop A is connected to your standard home Wi-Fi router.
2. Run an audit against a public control server (e.g. `1.1.1.1` or your VPS) and export the report:
   ```powershell
   # Windows PowerShell (Laptop A) [FROM CODE]
   netpolicy audit --target 1.1.1.1 --ports 25,80,443,587 --runs 3 --output reports/home_wifi.json --json
   ```
   *(Record the run ID output in the terminal, e.g. `run_id: 20261119-120000-abcdef`)*

### Phase 2: Audit Mobile Hotspot (Laptop A on Phone Tethering)
1. Disconnect Laptop A from home Wi-Fi.
2. Enable Mobile Hotspot on your smartphone and connect Laptop A to the cellular Wi-Fi hotspot.
3. Re-run the identical audit and export to a second report file:
   ```powershell
   # Windows PowerShell (Laptop A) [FROM CODE]
   netpolicy audit --target 1.1.1.1 --ports 25,80,443,587 --runs 3 --output reports/mobile_hotspot.json --json
   ```

### Phase 3: Diff Network Policies Using `netpolicy compare`

#### Using the CLI:
```powershell
# Windows PowerShell (Laptop A) [FROM CODE]
netpolicy compare reports/home_wifi.json reports/mobile_hotspot.json
```

#### Using the Interactive Wizard:
1. Run `netpolicy`.
2. In `MAIN_MENU`, select: `5 Compare two earlier checks`.
3. In `PICK_RUN_A`, select the Home Wi-Fi report (`home_wifi.jsonl`).
4. In `PICK_RUN_B`, select the Mobile Hotspot report (`mobile_hotspot.jsonl`).
5. In `REVIEW`, select: `1 Run now`.

#### Expected Difference Output:
The comparison view will display policy shifts between the networks:
- Cellular networks typically block outbound SMTP (`Port 25: DROPPED`), whereas residential connections may leave submission ports open.
- Cellular carrier DNS resolvers may fail the `.invalid` NXDOMAIN test by returning search portal IP addresses.

---

## 7. Step 6: Mandatory Teardown & Cleanup Checklist

Immediately following test completion, execute these cleanup commands on Laptop B to restore default network security:

- [ ] **Stop Python Listeners (Laptop B)**:  
  Press `Ctrl+C` in Terminal 1 (port 8080) and Terminal 2 (port 2222).

- [ ] **Delete Firewall DROP Rule (Laptop B)**:  
  - If Windows Defender Firewall was used (PowerShell as Administrator on Laptop B):
    ```powershell
    # Windows PowerShell as Administrator (Laptop B) [UNVERIFIED on 2nd laptop]
    Remove-NetFirewallRule -DisplayName "NetPolicy-Test-Drop-9090"
    ```
    *Verify removal: `Get-NetFirewallRule -DisplayName "NetPolicy-Test-Drop-9090"` returns nothing.*
  - If Linux `iptables` was used (Laptop B):
    ```bash
    # Linux / WSL as root (Laptop B) [UNVERIFIED on 2nd laptop]
    sudo iptables -D INPUT -p tcp --dport 9090 -j DROP
    ```

- [ ] **Remove Local Packet Captures & Reports (Laptop A)**:  
  ```powershell
  # Windows PowerShell (Laptop A) [VERIFIED command shape]
  Remove-Item reports/capture-*.pcap -ErrorAction SilentlyContinue
  Remove-Item reports/home_wifi.json, reports/mobile_hotspot.json -ErrorAction SilentlyContinue
  ```
