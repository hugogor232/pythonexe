#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi AP Finder - Version avec Reset PoE
Intègre: fromCsvToHuman + testDNA + testPrime + Reset PoE via Tera Term
"""

import tkinter as tk
from tkinter import messagebox, simpledialog
import csv
import os
import json
import re
import sys
import threading
import argparse
import urllib.request
import urllib.error
import urllib.parse
import ssl
import base64
import socket
import http.cookiejar
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser
import time
import paramiko
from paramiko.channel import Channel

# ================================================================================
# CONFIGURATION GLOBALE
# ================================================================================

# Configuration SSH Rebond
SSH_CONFIG = {
    "rebond_host": "10.57.116.4",
    "rebond_port": 22,
    "timeout": 30,
}

# Table de correspondance IP -> Nom de contrôleur (pour données DNA)
CONTROLLER_IP_TO_NAME = {
    "10.250.255.31": "PST-CW-WLC01",
    "10.250.255.32": "PST-CW-WLC02",
    "10.250.255.33": "PST-CW-WLC03",
    "10.250.255.34": "PST-CW-WLC04",
    "10.250.255.35": "PST-CW-WLC05",
    "10.250.255.36": "PST-CW-WLC06",
    "10.250.255.37": "PST-CW-WLC07",
    "10.250.255.38": "PST-CW-WLC08",
    "10.250.255.39": "PST-CW-WLC09",
    "10.134.96.3":  "PST-CW-WLC-INT",
    "10.250.255.44": "PST-CW-WLC11",
    "10.250.255.45": "PST-CW-WLC12",
    "10.250.255.30": "PST-CW-WLC13",
    "10.134.96.8":  "PST-CW-WLC-INT2",
    "10.134.96.81": "PST-CW-WLCPP-8540",
}

# URLs des contrôleurs
CONTROLLER_URLS = {
    "WLC01": "https://cd0a0nnn53.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC02": "https://cd0a0nn528.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC03": "https://cd0a0np02d.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC04": "https://cd0a0nns4e.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC05": "https://cd0a0nnj57.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC06": "https://cd0bsctw5e.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC07": "https://cd0bsd822a.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC08": "https://cd0bsd0t4c.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC09": "https://cd0bsdat4c.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC-INT": "https://cd0d1xpx75.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "WLC11": "https://cd0klgv297.rp-laposte.apps.ocn.infra.ftgroup/webui/",
    "WLC12": "https://cd0klgt297.rp-laposte.apps.ocn.infra.ftgroup/",
    "WLC13": "https://cd0klgqkee.rp-laposte.apps.ocn.infra.ftgroup/webui/",
    "PST-CW-WLC01": "https://cd0a0nnn53.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC02": "https://cd0a0nn528.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC03": "https://cd0a0np02d.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC04": "https://cd0a0nns4e.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC05": "https://cd0a0nnj57.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC06": "https://cd0bsctw5e.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC07": "https://cd0bsd822a.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC08": "https://cd0bsd0t4c.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC09": "https://cd0bsdat4c.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC-INT": "https://cd0d1xpx75.rp-laposte.apps.ocn.infra.ftgroup/screens/frameset.html",
    "PST-CW-WLC-INT2": "https://cd0lzq7cfd.rp-laposte.apps.ocn.infra.ftgroup/webui/#/dashboard",
    "PST-CW-WLC11": "https://cd0klgv297.rp-laposte.apps.ocn.infra.ftgroup/webui/",
    "PST-CW-WLC12": "https://cd0klgt297.rp-laposte.apps.ocn.infra.ftgroup/",
    "PST-CW-WLC13": "https://cd0klgqkee.rp-laposte.apps.ocn.infra.ftgroup/webui/",
}

# ================================================================================
# THÈME COULEURS GUI
# ================================================================================
COLORS = {
    "bg_dark": "#1a1d23",
    "bg_medium": "#242830",
    "bg_light": "#2d323c",
    "bg_input": "#363c48",
    "accent_blue": "#3b82f6",
    "accent_blue_hover": "#2563eb",
    "accent_green": "#10b981",
    "accent_green_hover": "#059669",
    "accent_orange": "#f59e0b",
    "accent_orange_hover": "#d97706",
    "accent_gray": "#6b7280",
    "accent_gray_hover": "#4b5563",
    "accent_red": "#ef4444",
    "accent_red_hover": "#dc2626",
    "accent_purple": "#8b5cf6",
    "accent_purple_hover": "#7c3aed",
    "accent_cyan": "#06b6d4",
    "accent_cyan_hover": "#0891b2",
    "accent_yellow": "#eab308",
    "accent_yellow_hover": "#ca8a04",
    "text_primary": "#f3f4f6",
    "text_secondary": "#9ca3af",
    "text_muted": "#6b7280",
    "border": "#374151",
    "border_focus": "#3b82f6",
}

# ================================================================================
# DNA CONFIGURATION
# ================================================================================
DNA_LIST = ["dna1", "dna2", "dna3"]
DNA_BASE_URL_TEMPLATE = "https://pst-cw-{dna}.rp-laposte.apps.ocn.infra.ftgroup"
DNA_ENDPOINT_ROGUE_PATH = "/dna/intent/api/v1/security/rogue/wireless-containment/status"
DNA_ENDPOINT_DEVICES_PATH = "/api/v1/network-device?"
DNA_ENDPOINT_WI_INTENT_TPL = "/dna/intent/api/v1/network-device/{id}/wireless-info?"
DNA_ENDPOINT_WI_API_TPL = "/api/v1/network-device/{id}/wireless-info?"
DNA_OUTPUT_DIR = "downloads"
DNA_WIRELESS_INFO_ALL_FILE = os.path.join(DNA_OUTPUT_DIR, "dna_wireless_info_all.txt")
DNA_VERIFY_SSL = False
DNA_USE_SYSTEM_PROXY = False
DNA_TIMEOUT = 30
DNA_DEBUG = False

# ================================================================================
# PRIME CONFIGURATION
# ================================================================================
PRIME_CONFIG = {
    "prime1": {"base_url": "https://pst-cw-prime01.rp-laposte.apps.ocn.infra.ftgroup", "output_dir": "downloads/prime1"},
    "prime2": {"base_url": "https://pst-cw-prime02.rp-laposte.apps.ocn.infra.ftgroup", "output_dir": "downloads/prime2"},
    "prime3": {"base_url": "https://pst-cw-prime03.rp-laposte.apps.ocn.infra.ftgroup", "output_dir": "downloads/prime3"},
    "prime4": {"base_url": "https://pst-cw-prime04.rp-laposte.apps.ocn.infra.ftgroup", "output_dir": "downloads/prime4"},
}
PRIME_AP_DETAILS_PATH = "/webacs/api/v2/data/AccessPointDetails"
PRIME_TIMEOUT = 30
PRIME_ACCEPT_XML_WIDE = "application/xml, text/xml;q=0.9, */*;q=0.8"

# ================================================================================
# MODULE DNA - Fonctions de collecte DNA Center
# ================================================================================

def dna_create_opener(verify_ssl: bool, use_system_proxy: bool):
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if use_system_proxy:
        handlers.insert(0, urllib.request.ProxyHandler())
    else:
        handlers.insert(0, urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def dna_perform_request(opener, method, url, headers=None, data=None, timeout=DNA_TIMEOUT):
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "Mozilla/5.0 (urllib)")
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", resp.getcode())
            reason = getattr(resp, "reason", "")
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8", errors="ignore")
            return status, reason, ctype, resp.headers, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, e.reason, getattr(e, "headers", {}).get("Content-Type", ""), getattr(e, "headers", {}), body
    except urllib.error.URLError as e:
        return 0, str(e.reason), "", {}, ""


def dna_get_token(opener, base_url: str, username: str, password: str):
    url = base_url.rstrip("/") + "/dna/system/api/v1/auth/token"
    cred = f"{username}:{password}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Basic " + base64.b64encode(cred.encode()).decode(),
    }
    status, reason, ctype, hdrs, body = dna_perform_request(opener, "POST", url, headers=headers)
    token = hdrs.get("X-Auth-Token")
    if not token:
        try:
            j = json.loads(body)
            if isinstance(j, dict):
                token = j.get("Token") or j.get("token") or j.get("access_token")
        except Exception:
            pass
    return status, reason, token, body


def dna_get_json_by_url(opener, url: str, token: str):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Auth-Token": token,
    }
    status, reason, ctype, hdrs, body = dna_perform_request(opener, "GET", url, headers=headers)
    parsed = None
    if body:
        try:
            parsed = json.loads(body)
        except Exception:
            pass
    return status, reason, ctype, hdrs, parsed, body


def dna_fetch_all_devices_paginated(opener, base_url: str, token: str, user: str, pwd: str, page_size: int, max_pages: int):
    all_devices = []
    offset = 1
    page = 0
    
    while page < max_pages:
        if offset == 1:
            url = base_url.rstrip("/") + DNA_ENDPOINT_DEVICES_PATH
        else:
            url = base_url.rstrip("/") + DNA_ENDPOINT_DEVICES_PATH + f"/&offset={offset}&limit={page_size}"
        
        status, reason, ctype, hdrs, parsed, body = dna_get_json_by_url(opener, url, token)
        
        if status == 401:
            s, r, new_token, _ = dna_get_token(opener, base_url, user, pwd)
            if s == 200 and new_token:
                token = new_token
                continue
            break
        
        if status != 200 or parsed is None:
            break
        
        devices = []
        if isinstance(parsed, dict) and isinstance(parsed.get("response"), list):
            devices = parsed["response"]
        elif isinstance(parsed, list):
            devices = parsed
        
        if not devices:
            break
        
        all_devices.extend(devices)
        
        if len(devices) < page_size:
            break
        
        offset += page_size
        page += 1
    
    return all_devices


def dna_fetch_wireless_info_for_devices(opener, base_url: str, token: str, user: str, pwd: str, 
                                         devices: list, max_ap: int = 0, workers: int = 10,
                                         progress_callback=None):
    aps = [d for d in devices if isinstance(d, dict) and (d.get("family") or "").lower() == "unified ap"]
    
    if max_ap > 0:
        aps = aps[:max_ap]
    
    if not aps:
        return [], 0, 0
    
    entries = []
    counters = {"ok": 0, "err": 0, "done": 0}
    total_to_process = len(aps)
    
    token_lock = threading.Lock()
    counter_lock = threading.Lock()
    current_token = {"value": token}
    
    def fetch_one(ap):
        dev_id = ap.get("id") or ap.get("instanceUuid")
        hostname = ap.get("hostname") or ""
        
        if not dev_id:
            return None
        
        with token_lock:
            tok = current_token["value"]
        
        url1 = base_url.rstrip("/") + DNA_ENDPOINT_WI_INTENT_TPL.format(id=dev_id)
        s1, r1, ct1, h1, j1, b1 = dna_get_json_by_url(opener, url1, tok)
        
        if s1 == 401:
            with token_lock:
                ns, nr, new_tok, _ = dna_get_token(opener, base_url, user, pwd)
                if ns == 200 and new_tok:
                    current_token["value"] = new_tok
                    tok = new_tok
            s1, r1, ct1, h1, j1, b1 = dna_get_json_by_url(opener, url1, tok)
        
        if s1 == 200 and j1:
            return {"device": ap, "status": s1, "data": j1}
        
        url2 = base_url.rstrip("/") + DNA_ENDPOINT_WI_API_TPL.format(id=dev_id)
        s2, r2, ct2, h2, j2, b2 = dna_get_json_by_url(opener, url2, tok)
        
        if s2 == 200 and j2:
            return {"device": ap, "status": s2, "data": j2}
        
        return {"device": ap, "status": s1 or s2, "data": None, "error": f"HTTP {s1}/{s2}"}
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(fetch_one, ap): ap for ap in aps}
        
        for future in as_completed(futures):
            try:
                result = future.result()
                with counter_lock:
                    counters["done"] += 1
                    if result and result.get("status") == 200:
                        counters["ok"] += 1
                        entries.append(result)
                    else:
                        counters["err"] += 1
                    
                    if progress_callback and counters["done"] % 50 == 0:
                        progress_callback(counters["done"], total_to_process)
            except Exception:
                with counter_lock:
                    counters["done"] += 1
                    counters["err"] += 1
    
    return entries, counters["ok"], counters["err"]


def dna_save_text(filepath: str, content: str):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)


def dna_process_single(dna_name: str, opener, user: str, pwd: str, page_size: int, max_pages: int, 
                       max_ap: int = 0, skip_wireless_info: bool = False, workers: int = 10,
                       progress_callback=None) -> dict:
    base_url = DNA_BASE_URL_TEMPLATE.format(dna=dna_name)
    result = {
        "dna": dna_name,
        "base_url": base_url,
        "success": False,
        "error": None,
        "devices": None,
        "wireless_info": None,
        "output_file": None
    }
    
    token = None
    try:
        s, r, token, tok_body = dna_get_token(opener, base_url, user, pwd)
        if s != 200 or not token:
            result["error"] = f"Auth échouée HTTP {s} {r}"
            return result
        
        devices = dna_fetch_all_devices_paginated(opener, base_url, token, user, pwd, page_size, max_pages)
        result["devices"] = {"count": len(devices)}
        
        devices_json_file = os.path.join(DNA_OUTPUT_DIR, dna_name, "devices_raw.json")
        dna_save_text(devices_json_file, json.dumps(devices, indent=2, ensure_ascii=False))
        
        if skip_wireless_info:
            wireless_entries, ok_count, err_count = [], 0, 0
        else:
            wireless_entries, ok_count, err_count = dna_fetch_wireless_info_for_devices(
                opener, base_url, token, user, pwd, devices, max_ap, workers, progress_callback
            )
        result["wireless_info"] = {"count": len(wireless_entries), "entries": wireless_entries}
        
        ts = datetime.now().isoformat(timespec="seconds")
        parts = [f"# DNA API dump - {dna_name.upper()}\n# Date: {ts}\n# Base URL: {base_url}\n\n"]
        parts.append("## Network Devices\n")
        parts.append(f"# Total devices: {len(devices)}\n")
        parts.append(json.dumps({"response": devices}, indent=2, ensure_ascii=False))
        
        output_file = os.path.join(DNA_OUTPUT_DIR, dna_name, "dna_rogue_and_devices.txt")
        dna_save_text(output_file, "\n".join(parts))
        result["output_file"] = output_file
        result["success"] = True
        
    except Exception as e:
        result["error"] = f"Exception: {str(e)}"
    
    return result


def run_dna_collection(user: str, pwd: str, workers: int = 10, progress_callback=None) -> tuple:
    try:
        opener = dna_create_opener(DNA_VERIFY_SSL, DNA_USE_SYSTEM_PROXY)
        
        results = []
        for dna_name in DNA_LIST:
            r = dna_process_single(dna_name, opener, user, pwd, 
                                   page_size=500, max_pages=200, 
                                   max_ap=0, skip_wireless_info=False, 
                                   workers=workers, progress_callback=progress_callback)
            results.append(r)
        
        ts = datetime.now().isoformat(timespec="seconds")
        parts = [f"# DNA Wireless Info (agrégé)\n# Date: {ts}\n\n"]
        total_entries = 0
        
        for r in results:
            parts.append(f"## {r['dna'].upper()} - Base URL: {r.get('base_url','')}\n")
            if r.get("wireless_info") and isinstance(r["wireless_info"].get("entries"), list):
                entries = r["wireless_info"]["entries"]
                total_entries += len(entries)
                parts.append(f"# Count: {len(entries)}\n")
                parts.append(json.dumps(entries, indent=2, ensure_ascii=False))
            else:
                parts.append("# Count: 0\n[]")
            parts.append("\n\n")
        
        dna_save_text(DNA_WIRELESS_INFO_ALL_FILE, "\n".join(parts))
        
        success_count = sum(1 for r in results if r["success"])
        total_devices = sum(r.get("devices", {}).get("count", 0) for r in results)
        
        if success_count == len(DNA_LIST):
            return True, f"DNA: OK - {total_devices} devices, {total_entries} wireless-info"
        elif success_count > 0:
            return True, f"DNA: Partiel ({success_count}/{len(DNA_LIST)}) - {total_devices} devices"
        else:
            errors = [r.get("error", "inconnu") for r in results if not r["success"]]
            return False, f"DNA: Échec - {errors[0] if errors else 'inconnu'}"
    
    except Exception as e:
        return False, f"DNA: Exception - {str(e)}"


# ================================================================================
# MODULE PRIME - Fonctions de collecte Prime
# ================================================================================

def prime_create_opener(verify_ssl: bool, use_system_proxy: bool):
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    cj = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx)]
    if use_system_proxy:
        handlers.insert(0, urllib.request.ProxyHandler())
    else:
        handlers.insert(0, urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def prime_basic_auth_header(user: str, pwd: str) -> str:
    token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"


def prime_get_xml_page(opener, base_url: str, path: str, params: dict, auth_header: str):
    q = "&".join(f"{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}" for k, v in params.items())
    url = f"{base_url.rstrip('/')}{path}?{q}"
    
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": PRIME_ACCEPT_XML_WIDE,
        "Authorization": auth_header,
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=PRIME_TIMEOUT) as resp:
            code = resp.getcode()
            body = resp.read()
            if code != 200:
                return code, None, f"HTTP {code}"
            try:
                content = body.decode("utf-8", errors="ignore")
                root = ET.fromstring(content)
                return 200, root, None
            except ET.ParseError as pe:
                return 200, None, f"XML ParseError: {pe}"
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTPError: HTTP {e.code}"
    except Exception as e:
        return 0, None, f"{type(e).__name__}: {e}"


def prime_extract_total_count(root):
    if root is not None:
        if root.tag.endswith("queryResponse"):
            try:
                return int(root.attrib.get("count"))
            except Exception:
                pass
        for node in root.iter():
            if isinstance(node.tag, str) and node.tag.endswith("queryResponse"):
                try:
                    return int(node.attrib.get("count"))
                except Exception:
                    pass
    return None


def prime_get_deep_text(parent, local_names):
    if parent is None:
        return ""
    if isinstance(local_names, str):
        local_names = [local_names]
    for node in parent.iter():
        if isinstance(node.tag, str) and any(node.tag.endswith(n) for n in local_names):
            val = (node.text or "").strip()
            if val:
                return val
    return ""


def prime_iter_ap_entries(root):
    if root is None:
        return
    for ap in root.iter():
        if isinstance(ap.tag, str) and ap.tag.endswith("accessPointDetailsDTO"):
            yield {
                "name": prime_get_deep_text(ap, "name"),
                "controllerName": prime_get_deep_text(ap, ["controllerName", "wlcName", "controller"]),
                "neighborName": prime_get_deep_text(ap, ["neighborName", "cdpNeighborName", "cdpNeighborDeviceName"]),
                "neighborPort": prime_get_deep_text(ap, ["neighborPort", "cdpNeighborPort"]),
                "neighborIpAddress": prime_get_deep_text(ap, ["neighborIpAddress", "cdpNeighborIpAddress", "cdpNeighborAddress", "neighborAddress"]),
                "ethernetMacAddress": prime_get_deep_text(ap, ["ethernetMacAddress", "ethernetMac", "macAddress", "baseMacAddress", "apEthernetMacAddress"]),
                "ipAddress": prime_get_deep_text(ap, ["ipAddress", "managementIpAddress", "apIpAddress"]),
            }


def prime_write_csv(output_dir: str, rows: list):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"AP_Inventory_{ts}.csv"
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("AP Inventory\n")
        f.write("AP Name,Neighbor Name,Neighbor Address,Neighbor Port,Controller Name,MAC Address,IP Address\n")
        for r in rows:
            def esc(v):
                v = (v or "").replace("\n", " ").strip()
                if ("," in v) or ('"' in v):
                    v = '"' + v.replace('"', '""') + '"'
                return v
            f.write(f"{esc(r.get('name'))},{esc(r.get('neighborName'))},{esc(r.get('neighborIpAddress'))},{esc(r.get('neighborPort'))},{esc(r.get('controllerName'))},{esc(r.get('ethernetMacAddress'))},{esc(r.get('ipAddress'))}\n")
    return path


def prime_purge_old_csvs(dir_path: str):
    try:
        os.makedirs(dir_path, exist_ok=True)
        for fn in os.listdir(dir_path):
            if fn.lower().endswith(".csv"):
                try:
                    os.remove(os.path.join(dir_path, fn))
                except Exception:
                    pass
    except Exception:
        pass


def prime_fetch_inventory(base_url: str, user: str, pwd: str, page_size: int = 500):
    opener = prime_create_opener(verify_ssl=False, use_system_proxy=False)
    auth = prime_basic_auth_header(user, pwd)
    
    params = {".full": "true", ".firstResult": 0, ".maxResults": page_size}
    status, root, err = prime_get_xml_page(opener, base_url, PRIME_AP_DETAILS_PATH, params, auth)
    
    if status != 200 or root is None:
        return []
    
    total = prime_extract_total_count(root)
    rows = list(prime_iter_ap_entries(root))
    fetched = len(rows)
    
    page_index = 1
    while (total is None) or (fetched < total):
        params = {".full": "true", ".firstResult": fetched, ".maxResults": page_size}
        status, root, err = prime_get_xml_page(opener, base_url, PRIME_AP_DETAILS_PATH, params, auth)
        if status != 200 or root is None:
            break
        new_rows = list(prime_iter_ap_entries(root))
        if not new_rows:
            break
        rows.extend(new_rows)
        fetched += len(new_rows)
        page_index += 1
        if total is None and len(new_rows) < page_size:
            break
    
    return rows


def run_prime_collection(user: str, pwd: str) -> tuple:
    try:
        written = []
        for name, cfg in PRIME_CONFIG.items():
            base_url = cfg["base_url"].rstrip("/")
            output_dir = cfg.get("output_dir") or f"downloads/{name}"
            
            rows = prime_fetch_inventory(base_url, user, pwd)
            if rows:
                prime_purge_old_csvs(output_dir)
                path = prime_write_csv(output_dir, rows)
                written.append((name, len(rows)))
        
        if written:
            total_aps = sum(count for _, count in written)
            return True, f"Prime: OK - {len(written)}/{len(PRIME_CONFIG)} instances, {total_aps} APs"
        else:
            return False, "Prime: Aucun AP récupéré"
    
    except Exception as e:
        return False, f"Prime: Exception - {str(e)}"


# ================================================================================
# MODULE SSH - Connexion via Paramiko avec rebond
# ================================================================================

class SSHSwitchClient:
    """Client SSH pour connexion aux switches via rebond"""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.rebond_client = None
        self.target_client = None
        self.shell = None
        self.log_content = ""
    
    def _log(self, message: str):
        """Ajoute un message au log"""
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_content += f"[{ts}] {message}\n"
    
    def connect_rebond(self) -> bool:
        """Connexion au serveur de rebond"""
        try:
            self.rebond_client = paramiko.SSHClient()
            self.rebond_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.rebond_client.connect(
                hostname=SSH_CONFIG["rebond_host"],
                port=SSH_CONFIG["rebond_port"],
                username=self.username,
                password=self.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=SSH_CONFIG["timeout"],
            )
            self._log(f"Connecté au rebond {SSH_CONFIG['rebond_host']}")
            return True
        except Exception as e:
            self._log(f"ERREUR rebond: {str(e)}")
            return False
    
    def connect_target(self, target_ip: str) -> bool:
        """Connexion au switch cible via le rebond"""
        if not self.rebond_client:
            self._log("ERREUR: Non connecté au rebond")
            return False
        
        try:
            transport = self.rebond_client.get_transport()
            jump_channel: Channel = transport.open_channel(
                "direct-tcpip",
                (target_ip, 22),
                ("127.0.0.1", 0),
            )
            
            self.target_client = paramiko.SSHClient()
            self.target_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.target_client.connect(
                hostname=target_ip,
                username=self.username,
                password=self.password,
                sock=jump_channel,
                look_for_keys=False,
                allow_agent=False,
                timeout=SSH_CONFIG["timeout"],
            )
            self._log(f"Connecté au switch {target_ip}")
            return True
        except Exception as e:
            self._log(f"ERREUR connexion switch: {str(e)}")
            return False
    
    def open_shell(self) -> bool:
        """Ouvre un shell interactif"""
        if not self.target_client:
            return False
        
        try:
            self.shell = self.target_client.invoke_shell(width=200, height=50)
            self.shell.settimeout(SSH_CONFIG["timeout"])
            time.sleep(0.5)
            if self.shell.recv_ready():
                self.shell.recv(65535)
            self._log("Shell ouvert")
            return True
        except Exception as e:
            self._log(f"ERREUR shell: {str(e)}")
            return False
    
    def send_command(self, command: str, wait_time: float = 1.0) -> str:
        """Envoie une commande et retourne la sortie"""
        if not self.shell:
            return ""
        
        self.shell.send(command + "\n")
        time.sleep(wait_time)
        
        output = ""
        max_loops = 50
        loops = 0
        
        while loops < max_loops:
            if self.shell.recv_ready():
                chunk = self.shell.recv(65535).decode('utf-8', errors='ignore')
                output += chunk
                if re.search(r'[>#]', output.split('\n')[-1]):
                    break
            else:
                time.sleep(0.1)
            loops += 1
        
        return output
    
    def close(self):
        """Ferme toutes les connexions"""
        if self.shell:
            try:
                self.shell.close()
            except:
                pass
        if self.target_client:
            try:
                self.target_client.close()
            except:
                pass
        if self.rebond_client:
            try:
                self.rebond_client.close()
            except:
                pass
        self._log("Connexions fermées")


# ================================================================================
# GUI - Interface graphique
# ================================================================================

class ModernButton(tk.Canvas):
    def __init__(self, parent, text, command, bg_color, hover_color, width=140, height=38, **kwargs):
        super().__init__(parent, width=width, height=height, bg=COLORS["bg_medium"], highlightthickness=0, **kwargs)
        self.command = command
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.text = text
        self.width = width
        self.height = height
        self.current_color = bg_color
        self._enabled = True
        self.draw_button()
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
    
    def draw_button(self):
        self.delete("all")
        radius = 6
        self.create_rounded_rect(2, 2, self.width-2, self.height-2, radius, fill=self.current_color, outline="")
        self.create_text(self.width//2, self.height//2, text=self.text, fill="white", font=("Segoe UI", 10, "bold"))
    
    def create_rounded_rect(self, x1, y1, x2, y2, radius, **kwargs):
        points = [x1+radius, y1, x2-radius, y1, x2, y1, x2, y1+radius, x2, y2-radius, x2, y2, x2-radius, y2,
                  x1+radius, y2, x1, y2, x1, y2-radius, x1, y1+radius, x1, y1]
        return self.create_polygon(points, smooth=True, **kwargs)
    
    def on_enter(self, event):
        if self._enabled:
            self.current_color = self.hover_color
            self.draw_button()
            self.config(cursor="hand2")
    
    def on_leave(self, event):
        if self._enabled:
            self.current_color = self.bg_color
            self.draw_button()
    
    def on_click(self, event):
        if self._enabled and self.command:
            self.command()
    
    def set_state(self, state):
        if state == "disabled":
            self._enabled = False
            self.current_color = COLORS["accent_gray"]
        else:
            self._enabled = True
            self.current_color = self.bg_color
        self.draw_button()


class WiFiAPFinder:
    def __init__(self):
        self.ap_data = {}
        self.switch_ip_map = {}
        
        self.current_result = {
            "switch_ip": "",
            "mac": "",
            "controller": "",
            "ap_name": "",
            "port": "",
            "switch": "",
        }
        
        self.csv_dirs = [
            os.path.join("downloads", "prime1"),
            os.path.join("downloads", "prime2"),
            os.path.join("downloads", "prime3"),
            os.path.join("downloads", "prime4"),
        ]
        
        self.dna_dirs = [
            os.path.join("downloads", "dna1"),
            os.path.join("downloads", "dna2"),
            os.path.join("downloads", "dna3"),
        ]
        self.default_dna_filename = "dna_rogue_and_devices.txt"
        self.wireless_info_path = os.path.join("downloads", "dna_wireless_info_all.txt")
        self.report_sw_path = os.path.join("downloads", "Report-SW.csv")
        
        self.loaded_files = []
        
        self.setup_gui()
        self.load_all_data()

    def run(self):
        self.window.mainloop()

    def setup_gui(self):
        self.window = tk.Tk()
        self.window.title("WiFi AP Finder + Reset PoE")
        self.window.geometry("1150x700")
        self.window.configure(bg=COLORS["bg_dark"])
        self.window.resizable(True, True)
        self.window.minsize(950, 550)
        self.center_window()

        main_container = tk.Frame(self.window, bg=COLORS["bg_dark"])
        main_container.pack(fill="both", expand=True, padx=20, pady=15)

        # Status card (compact)
        status_card = tk.Frame(main_container, bg=COLORS["bg_medium"], padx=15, pady=10)
        status_card.pack(fill="x", pady=(0, 10))
        status_header = tk.Frame(status_card, bg=COLORS["bg_medium"])
        status_header.pack(fill="x")
        self.status_icon = tk.Label(status_header, text="●", font=("Segoe UI", 10),
                                    bg=COLORS["bg_medium"], fg=COLORS["accent_green"])
        self.status_icon.pack(side="left")
        tk.Label(status_header, text=" Sources de données", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg_medium"], fg=COLORS["text_primary"]).pack(side="left")
        self.file_status_label = tk.Label(status_card, text="Chargement...", font=("Segoe UI", 9),
                                          bg=COLORS["bg_medium"], fg=COLORS["text_secondary"],
                                          justify="left", anchor="w")
        self.file_status_label.pack(fill="x", pady=(5, 0))

        # Search card
        search_card = tk.Frame(main_container, bg=COLORS["bg_medium"], padx=15, pady=12)
        search_card.pack(fill="x", pady=(0, 10))
        
        # Ligne recherche + mot de passe
        search_row = tk.Frame(search_card, bg=COLORS["bg_medium"])
        search_row.pack(fill="x", pady=(0, 8))
        
        # Colonne recherche
        search_col = tk.Frame(search_row, bg=COLORS["bg_medium"])
        search_col.pack(side="left", fill="x", expand=True)
        
        tk.Label(search_col, text="Nom de la borne WiFi ou Hostname", font=("Segoe UI", 10),
                 bg=COLORS["bg_medium"], fg=COLORS["text_primary"]).pack(anchor="w", pady=(0, 4))
        
        input_row = tk.Frame(search_col, bg=COLORS["bg_medium"])
        input_row.pack(fill="x")
        input_container = tk.Frame(input_row, bg=COLORS["border"], padx=1, pady=1)
        input_container.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entry_ap = tk.Entry(input_container, font=("Segoe UI", 11), bg=COLORS["bg_input"],
                                 fg=COLORS["text_primary"], insertbackground=COLORS["text_primary"],
                                 relief="flat", borderwidth=0)
        self.entry_ap.pack(fill="x", ipady=8, ipadx=10)
        self.entry_ap.bind("<Return>", lambda event: self.search_ap())
        self.entry_ap.bind("<FocusIn>", lambda e: input_container.config(bg=COLORS["border_focus"]))
        self.entry_ap.bind("<FocusOut>", lambda e: input_container.config(bg=COLORS["border"]))

        self.search_btn = ModernButton(input_row, text="🔍 Rechercher", command=self.search_ap,
                                       bg_color=COLORS["accent_blue"], hover_color=COLORS["accent_blue_hover"],
                                       width=110, height=36)
        self.search_btn.pack(side="left")
        
        # Colonne credentials SSH
        cred_col = tk.Frame(search_row, bg=COLORS["bg_medium"])
        cred_col.pack(side="right", padx=(20, 0))
        
        tk.Label(cred_col, text="Credentials SSH (user / mdp)", font=("Segoe UI", 10),
                 bg=COLORS["bg_medium"], fg=COLORS["text_primary"]).pack(anchor="w", pady=(0, 4))
        
        cred_row = tk.Frame(cred_col, bg=COLORS["bg_medium"])
        cred_row.pack(fill="x")
        
        user_container = tk.Frame(cred_row, bg=COLORS["border"], padx=1, pady=1)
        user_container.pack(side="left", padx=(0, 5))
        self.entry_user = tk.Entry(user_container, font=("Segoe UI", 10), bg=COLORS["bg_input"],
                                   fg=COLORS["text_primary"], insertbackground=COLORS["text_primary"],
                                   relief="flat", borderwidth=0, width=14)
        self.entry_user.pack(fill="x", ipady=6, ipadx=8)
        self.entry_user.bind("<FocusIn>", lambda e: user_container.config(bg=COLORS["border_focus"]))
        self.entry_user.bind("<FocusOut>", lambda e: user_container.config(bg=COLORS["border"]))
        
        pwd_container = tk.Frame(cred_row, bg=COLORS["border"], padx=1, pady=1)
        pwd_container.pack(side="left")
        self.entry_pwd = tk.Entry(pwd_container, font=("Segoe UI", 10), bg=COLORS["bg_input"],
                                  fg=COLORS["text_primary"], insertbackground=COLORS["text_primary"],
                                  relief="flat", borderwidth=0, show="*", width=14)
        self.entry_pwd.pack(fill="x", ipady=6, ipadx=8)
        self.entry_pwd.bind("<FocusIn>", lambda e: pwd_container.config(bg=COLORS["border_focus"]))
        self.entry_pwd.bind("<FocusOut>", lambda e: pwd_container.config(bg=COLORS["border"]))

        # LIGNE DES BOUTONS
        buttons_row = tk.Frame(search_card, bg=COLORS["bg_medium"])
        buttons_row.pack(fill="x", pady=(12, 0))
        
        # Boutons généraux
        self.clear_btn = ModernButton(buttons_row, text="🗑 Effacer", command=self.clear_fields,
                                      bg_color=COLORS["accent_orange"], hover_color=COLORS["accent_orange_hover"],
                                      width=90, height=32)
        self.clear_btn.pack(side="left", padx=(0, 8))
        
        self.copy_btn = ModernButton(buttons_row, text="📋 Tout", command=self.copy_to_clipboard,
                                     bg_color=COLORS["accent_green"], hover_color=COLORS["accent_green_hover"],
                                     width=80, height=32)
        self.copy_btn.pack(side="left", padx=(0, 8))
        self.copy_btn.set_state("disabled")
        
        self.refresh_btn = ModernButton(buttons_row, text="↻ Recharger", command=self.open_reload_dialog,
                                        bg_color=COLORS["accent_gray"], hover_color=COLORS["accent_gray_hover"],
                                        width=100, height=32)
        self.refresh_btn.pack(side="left", padx=(0, 20))
        
        # Séparateur visuel
        tk.Label(buttons_row, text="|", font=("Segoe UI", 12), bg=COLORS["bg_medium"], fg=COLORS["text_muted"]).pack(side="left", padx=(0, 20))
        
        # Boutons d'action rapide
        self.copy_ip_btn = ModernButton(buttons_row, text="📋 IP Switch", command=self.copy_switch_ip,
                                        bg_color=COLORS["accent_cyan"], hover_color=COLORS["accent_cyan_hover"],
                                        width=95, height=32)
        self.copy_ip_btn.pack(side="left", padx=(0, 8))
        self.copy_ip_btn.set_state("disabled")

        self.copy_ip_btn = ModernButton(buttons_row, text="📋 T5", command=self.t5command,
                                        bg_color=COLORS["accent_cyan"], hover_color=COLORS["accent_cyan_hover"],
                                        width=40, height=32)
        self.copy_ip_btn.pack(side="left", padx=(0, 8))
        self.copy_ip_btn.set_state("disabled")
        
        self.copy_mac_btn = ModernButton(buttons_row, text="📋 MAC", command=self.copy_mac,
                                         bg_color=COLORS["accent_purple"], hover_color=COLORS["accent_purple_hover"],
                                         width=80, height=32)
        self.copy_mac_btn.pack(side="left", padx=(0, 8))
        self.copy_mac_btn.set_state("disabled")
        
        self.open_controller_btn = ModernButton(buttons_row, text="🌐 Contrôleur", command=self.open_controller,
                                                bg_color=COLORS["accent_blue"], hover_color=COLORS["accent_blue_hover"],
                                                width=105, height=32)
        self.open_controller_btn.pack(side="left", padx=(0, 8))
        self.open_controller_btn.set_state("disabled")
        
        # Séparateur visuel
        tk.Label(buttons_row, text="|", font=("Segoe UI", 12), bg=COLORS["bg_medium"], fg=COLORS["text_muted"]).pack(side="left", padx=(0, 8))
        
        # BOUTON RESET POE
        self.reset_poe_btn = ModernButton(buttons_row, text="⚡ Reset PoE", command=self.reset_poe,
                                          bg_color=COLORS["accent_red"], hover_color=COLORS["accent_red_hover"],
                                          width=100, height=32)
        self.reset_poe_btn.pack(side="left", padx=(0, 8))
        self.reset_poe_btn.set_state("disabled")
        # BOUTON MACRO 1

        self.macro1_btn = ModernButton(buttons_row, text="CDP NEI+POW IN", command=self.run_macro1,
                                       bg_color=COLORS["accent_yellow"], hover_color=COLORS["accent_yellow_hover"],
                                       width=120, height=32)
        self.macro1_btn.pack(side="left", padx=(0, 8))
        self.macro1_btn.set_state("disabled")
        
        # BOUTON MACRO 2
        self.macro2_btn = ModernButton(buttons_row, text="🔧 RESET+ATT", command=self.run_macro2,
                                       bg_color=COLORS["accent_purple"], hover_color=COLORS["accent_purple_hover"],
                                       width=120, height=32)
        self.macro2_btn.pack(side="left", padx=(0, 8))
        self.macro2_btn.set_state("disabled")
        
        # BOUTON MACRO 3
        self.macro3_btn = ModernButton(buttons_row, text="🔧 Macro 3", command=self.run_macro3,
                                       bg_color=COLORS["accent_cyan"], hover_color=COLORS["accent_cyan_hover"],
                                       width=90, height=32)
        self.macro3_btn.pack(side="left", padx=(0, 8))
        self.macro3_btn.set_state("disabled")
        # Label info contrôleur
        self.controller_info_label = tk.Label(buttons_row, text="", font=("Segoe UI", 9),
                                              bg=COLORS["bg_medium"], fg=COLORS["text_muted"])
        self.controller_info_label.pack(side="left", padx=(5, 0))

        # Result card
        result_card = tk.Frame(main_container, bg=COLORS["bg_medium"], padx=15, pady=12)
        result_card.pack(fill="both", expand=True)
        
        result_header = tk.Frame(result_card, bg=COLORS["bg_medium"])
        result_header.pack(fill="x", pady=(0, 8))
        tk.Label(result_header, text="Résultat", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg_medium"], fg=COLORS["text_primary"]).pack(side="left")
        self.copy_status_label = tk.Label(result_header, text="", font=("Segoe UI", 9),
                                          bg=COLORS["bg_medium"], fg=COLORS["accent_green"])
        self.copy_status_label.pack(side="right")

        result_text_container = tk.Frame(result_card, bg=COLORS["border"], padx=1, pady=1)
        result_text_container.pack(fill="both", expand=True)
        self.result_text = tk.Text(result_text_container, font=("Consolas", 11), bg=COLORS["bg_light"],
                                   fg=COLORS["text_secondary"], insertbackground=COLORS["text_primary"],
                                   relief="flat", borderwidth=0, wrap=tk.WORD, padx=12, pady=10, state="disabled")
        self.result_text.pack(fill="both", expand=True)
        self.last_result = ""

    def center_window(self):
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'+{x}+{y}')

    # ==================== RESET POE (Paramiko SSH) ====================
    
    def get_ssh_credentials(self):
        """Récupère les credentials SSH"""
        user = self.entry_user.get().strip()
        pwd = self.entry_pwd.get()
        if not user or not pwd:
            messagebox.showwarning("Attention", "Veuillez entrer vos credentials SSH (utilisateur et mot de passe).")
            self.entry_user.focus_set()
            return None, None
        return user, pwd
    
    def reset_poe(self):
        """Lance le reset PoE via SSH Paramiko"""
        switch_ip = self.current_result.get("switch_ip", "")
        port = self.current_result.get("port", "")
        switch_name = self.current_result.get("switch", "")
        ap_name = self.current_result.get("ap_name", "")
        
        if not switch_ip:
            self.show_copy_status("❌ Pas d'IP Switch", error=True)
            messagebox.showerror("Erreur", "Impossible de trouver l'IP du switch.")
            return
        
        if not port:
            self.show_copy_status("❌ Pas de port", error=True)
            messagebox.showerror("Erreur", "Impossible de trouver le port de la borne.")
            return
        
        user, pwd = self.get_ssh_credentials()
        if not user:
            return
        
        confirm_msg = f"Voulez-vous vraiment effectuer un Reset PoE ?\n\n"
        confirm_msg += f"Borne: {ap_name}\n"
        confirm_msg += f"Switch: {switch_name} ({switch_ip})\n"
        confirm_msg += f"Port: {port}\n\n"
        confirm_msg += "Cette action va:\n"
        confirm_msg += "• Couper l'alimentation PoE (shut + power inline never)\n"
        confirm_msg += "• Attendre 15 secondes\n"
        confirm_msg += "• Rétablir l'alimentation (no shut + power inline auto)"
        
        if not messagebox.askyesno("Confirmation Reset PoE", confirm_msg, icon="warning"):
            self.show_copy_status("Reset annulé")
            return
        
        self.set_ui_busy(True)
        self.show_copy_status("⚡ Reset PoE en cours...")
        
        def run_reset():
            ssh = SSHSwitchClient(user, pwd)
            ssh.log_content = f"=== RESET POE ===\nSwitch: {switch_ip}\nInterface: {port}\n{'='*40}\n"
            
            try:
                if not ssh.connect_rebond():
                    return False, "Échec connexion rebond", ssh.log_content
                
                if not ssh.connect_target(switch_ip):
                    return False, "Échec connexion switch", ssh.log_content
                
                if not ssh.open_shell():
                    return False, "Échec ouverture shell", ssh.log_content
                
                ssh.send_command("terminal length 0", 0.5)
                
                ssh._log(">>> conf t")
                ssh.send_command("conf t", 0.5)
                
                ssh._log(f">>> interface {port}")
                ssh.send_command(f"interface {port}", 0.5)
                
                ssh._log(">>> shutdown")
                ssh.send_command("shutdown", 0.5)
                
                ssh._log(">>> power inline never")
                ssh.send_command("power inline never", 0.5)
                
                ssh._log(">>> Attente 15 secondes...")
                time.sleep(15)
                
                ssh._log(">>> no shutdown")
                ssh.send_command("no shutdown", 0.5)
                
                ssh._log(">>> power inline auto")
                ssh.send_command("power inline auto", 0.5)
                
                ssh._log(">>> exit")
                ssh.send_command("exit", 0.5)
                ssh.send_command("exit", 0.5)
                
                ssh._log("=== RESET POE TERMINE ===")
                ssh.close()
                return True, "Reset PoE effectué avec succès", ssh.log_content
                
            except Exception as e:
                ssh._log(f"ERREUR: {str(e)}")
                ssh.close()
                return False, f"Erreur: {str(e)}", ssh.log_content
        
        def on_complete():
            success, message, log = run_reset()
            def update_ui():
                self.set_ui_busy(False)
                if success:
                    self.show_copy_status("✓ Reset PoE terminé")
                else:
                    self.show_copy_status(f"❌ {message}", error=True)
                self.display_poe_result(success, ap_name, switch_name, switch_ip, port, log if success else message)
            self.window.after(0, update_ui)
        
        threading.Thread(target=on_complete, daemon=True).start()
    
    def display_poe_result(self, success, ap_name, switch_name, switch_ip, port, log_content):
        """Affiche le résultat du reset PoE dans l'interface"""
        lines = []
        if success:
            lines.append("=" * 50)
            lines.append("✓ RESET POE EFFECTUÉ AVEC SUCCÈS")
            lines.append("=" * 50)
        else:
            lines.append("=" * 50)
            lines.append("❌ RESET POE ÉCHOUÉ")
            lines.append("=" * 50)
        
        lines.append("")
        lines.append(f"Borne: {ap_name}")
        lines.append(f"Switch: {switch_name} ({switch_ip})")
        lines.append(f"Interface: {port}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        if log_content:
            lines.append("─" * 50)
            lines.append("DÉTAIL DES COMMANDES:")
            lines.append("─" * 50)
            for line in log_content.split('\n'):
                if line.strip():
                    lines.append(line)
        
        self.display_result("\n".join(lines), success=success)
    
    # ==================== MACROS SSH ====================
    
    def run_macro1(self):
        """Show CDP neighbors + Power inline via SSH"""
        switch_ip = self.current_result.get("switch_ip", "")
        ap_name = self.current_result.get("ap_name", "")
        switch_name = self.current_result.get("switch", "")
        port = self.current_result.get("port", "")
        
        if not switch_ip:
            self.show_copy_status("❌ IP manquante", error=True)
            return
        
        user, pwd = self.get_ssh_credentials()
        if not user:
            return
        
        msg = f"Voulez-vous exécuter Show CDP + Power Inline ?\n\nSwitch: {switch_name} ({switch_ip})"
        if not messagebox.askyesno("Confirmation Macro 1", msg, icon="warning"):
            return
        
        self.set_ui_busy(True)
        self.show_copy_status("⚙️ Macro 1 en cours...")
        
        def do_macro():
            ssh = SSHSwitchClient(user, pwd)
            ssh.log_content = f"=== SHOW CDP NEI + POWER INLINE ===\nSwitch: {switch_ip}\n{'='*40}\n"
            
            try:
                if not ssh.connect_rebond():
                    return False, "Échec connexion rebond", ssh.log_content
                
                if not ssh.connect_target(switch_ip):
                    return False, "Échec connexion switch", ssh.log_content
                
                if not ssh.open_shell():
                    return False, "Échec ouverture shell", ssh.log_content
                
                ssh.send_command("terminal length 0", 0.5)
                
                ssh._log(">>> show cdp neighbors")
                ssh._log("-" * 30)
                output1 = ssh.send_command("show cdp neighbors", 2)
                ssh.log_content += output1 + "\n"
                
                ssh._log(">>> show power inline")
                ssh._log("-" * 30)
                output2 = ssh.send_command("show power inline", 2)
                ssh.log_content += output2 + "\n"
                
                ssh._log("=== TERMINE ===")
                ssh.close()
                return True, "Commandes exécutées", ssh.log_content
                
            except Exception as e:
                ssh._log(f"ERREUR: {str(e)}")
                ssh.close()
                return False, f"Erreur: {str(e)}", ssh.log_content
        
        def on_complete():
            success, message, log = do_macro()
            def update_ui():
                self.set_ui_busy(False)
                self.show_copy_status(f"✓ Macro 1 terminée" if success else f"❌ {message}", error=not success)
                self.display_macro_result(success, "Macro 1", ap_name, switch_name, switch_ip, port, log if success else message)
            self.window.after(0, update_ui)
        
        threading.Thread(target=on_complete, daemon=True).start()
    
    def run_macro2(self):
        """Reset PoE + Attente 3min + Vérification CDP"""
        switch_ip = self.current_result.get("switch_ip", "")
        port = self.current_result.get("port", "")
        ap_name = self.current_result.get("ap_name", "")
        switch_name = self.current_result.get("switch", "")
        
        if not switch_ip or not port:
            self.show_copy_status("❌ IP ou port manquant", error=True)
            return
        
        user, pwd = self.get_ssh_credentials()
        if not user:
            return
        
        msg = f"⚠️ Cette opération prend environ 3-4 minutes :\n"
        msg += f"• Reset PoE (15 sec)\n• Attente remontée borne (3 min)\n• Vérification CDP\n\n"
        msg += f"Borne: {ap_name}\nSwitch: {switch_name} ({switch_ip})\nPort: {port}"
        
        if not messagebox.askyesno("Confirmation Macro 2", msg, icon="warning"):
            return
        
        self.set_ui_busy(True)
        self.show_copy_status("⚙️ Reset + Vérification (~4 min)...")
        
        def do_macro():
            ssh = SSHSwitchClient(user, pwd)
            ssh.log_content = f"=== RESET POE + VERIFICATION ===\nSwitch: {switch_ip}\nInterface: {port}\nBorne: {ap_name}\n{'='*40}\n"
            
            try:
                if not ssh.connect_rebond():
                    return False, "Échec connexion rebond", ssh.log_content, False
                
                if not ssh.connect_target(switch_ip):
                    return False, "Échec connexion switch", ssh.log_content, False
                
                if not ssh.open_shell():
                    return False, "Échec ouverture shell", ssh.log_content, False
                
                ssh.send_command("terminal length 0", 0.5)
                
                # Phase 1: Reset PoE
                ssh._log("--- Phase 1: Reset PoE ---")
                ssh.send_command("conf t", 0.5)
                ssh.send_command(f"interface {port}", 0.5)
                ssh.send_command("shutdown", 0.5)
                ssh.send_command("power inline never", 0.5)
                ssh._log(">>> Attente 15 secondes...")
                time.sleep(15)
                ssh.send_command("no shutdown", 0.5)
                ssh.send_command("power inline auto", 0.5)
                ssh.send_command("exit", 0.5)
                ssh.send_command("exit", 0.5)
                
                # Phase 2: Attente
                ssh._log("--- Phase 2: Attente 180 secondes ---")
                time.sleep(180)
                
                # Phase 3: Vérification CDP
                ssh._log("--- Phase 3: Vérification CDP ---")
                output = ssh.send_command("show cdp neighbors", 2)
                ssh.log_content += output + "\n"
                
                ap_short = ap_name.split('.')[0] if '.' in ap_name else ap_name
                found = ap_short.lower() in output.lower()
                
                if found:
                    ssh._log(f">>> BORNE REMONTEE: {ap_short} trouvé <<<")
                    ssh._log("=== VERIFICATION REUSSIE ===")
                else:
                    ssh._log(f">>> BORNE NON DETECTEE: {ap_short} absent <<<")
                    ssh._log("=== VERIFICATION ECHOUEE ===")
                
                ssh.close()
                return True, f"{'Borne remontée' if found else 'Borne non détectée'}", ssh.log_content, found
                
            except Exception as e:
                ssh._log(f"ERREUR: {str(e)}")
                ssh.close()
                return False, f"Erreur: {str(e)}", ssh.log_content, False
        
        def on_complete():
            success, message, log, found = do_macro()
            def update_ui():
                self.set_ui_busy(False)
                if success and found:
                    self.show_copy_status("✓ Borne remontée !")
                    title = "✓ BORNE REMONTEE"
                elif success:
                    self.show_copy_status("⚠️ Borne non détectée", error=True)
                    title = "⚠️ BORNE NON DETECTEE"
                else:
                    self.show_copy_status(f"❌ {message}", error=True)
                    title = "❌ MACRO 2 ECHOUEE"
                
                self.display_macro_result(success and found, "Macro 2", ap_name, switch_name, switch_ip, port, log)
            self.window.after(0, update_ui)
        
        threading.Thread(target=on_complete, daemon=True).start()
    
    def run_macro3(self):
        """Placeholder pour macro3 - à personnaliser"""
        messagebox.showinfo("Macro 3", "Macro 3 non implémentée.\nPersonnalisez run_macro3() selon vos besoins.")
    
    def display_macro_result(self, success, macro_name, ap_name, switch_name, switch_ip, port, log_content):
        """Affiche le résultat d'une macro"""
        lines = []
        if success:
            lines.append("=" * 50)
            lines.append(f"✓ {macro_name.upper()} TERMINÉ")
            lines.append("=" * 50)
        else:
            lines.append("=" * 50)
            lines.append(f"❌ {macro_name.upper()} ÉCHOUÉ")
            lines.append("=" * 50)
        
        lines.append("")
        lines.append(f"Borne: {ap_name}")
        lines.append(f"Switch: {switch_name} ({switch_ip})")
        lines.append(f"Interface: {port}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        if log_content:
            lines.append("─" * 50)
            lines.append("DÉTAIL:")
            lines.append("─" * 50)
            for line in log_content.split('\n'):
                if line.strip():
                    lines.append(line)
        
        self.display_result("\n".join(lines), success=success)
    
    # ==================== ACTIONS RAPIDES ====================
    
    def copy_switch_ip(self):
        ip = self.current_result.get("switch_ip", "")
        if ip:
            self.copy_to_clipboard_text(ip)
            self.show_copy_status(f"✓ IP: {ip}")
        else:
            self.show_copy_status("❌ Pas d'IP", error=True)
    
    def t5command(self):
        ap_name = self.current_result.get("ap_name", "") or "PSTXXX"
        interface = self.current_result.get("port", "") or "port ?"
        switch_name = self.current_result.get("switch", "") or "switch ?"

        msg = (
            "Bonjour,\n\n"
            f"Suite à cet incident, la borne {ap_name} branchée sur le port {interface} du switch {switch_name} est injoignable.\n\n"
            "Merci d'intervenir afin de vérifier son état.\n\n"
            "Nous sommes en l'attente d'un retour de votre part.\n\n"
            "Cordialement,"
        )

        # Copie directement dans le presse-papiers (tu as déjà cette méthode dans ta classe)
        self.copy_to_clipboard_text(msg)
        # Optionnel : petit feedback visuel sur ton label existant
        self.show_copy_status("✓ Message T5 copié")


    def copy_mac(self):
        mac = self.current_result.get("mac", "")
        if mac:
            self.copy_to_clipboard_text(mac)
            self.show_copy_status(f"✓ MAC: {mac}")
        else:
            self.show_copy_status("❌ Pas de MAC", error=True)
    
    def open_controller(self):
        controller = self.current_result.get("controller", "")
        if not controller:
            self.show_copy_status("❌ Pas de contrôleur", error=True)
            return
        
        url = None
        if controller in CONTROLLER_URLS:
            url = CONTROLLER_URLS[controller]
        else:
            for key, value in CONTROLLER_URLS.items():
                if key in controller or controller in key:
                    url = value
                    break
        
        if url and not url.startswith("https://URL_"):
            webbrowser.open(url)
            self.show_copy_status(f"✓ {controller}")
        else:
            self.show_copy_status(f"❌ URL non configurée", error=True)
    
    def copy_to_clipboard_text(self, text):
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(text)
            self.window.update()
        except Exception:
            pass
    
    def show_copy_status(self, message, error=False):
        color = COLORS["accent_red"] if error else COLORS["accent_green"]
        self.copy_status_label.config(text=message, fg=color)
        self.window.after(5000, lambda: self.copy_status_label.config(text=""))
    
    def update_action_buttons(self):
        has_ip = bool(self.current_result.get("switch_ip"))
        has_mac = bool(self.current_result.get("mac"))
        has_controller = bool(self.current_result.get("controller"))
        has_port = bool(self.current_result.get("port"))
        
        self.copy_ip_btn.set_state("normal" if has_ip else "disabled")
        self.copy_mac_btn.set_state("normal" if has_mac else "disabled")
        self.open_controller_btn.set_state("normal" if has_controller else "disabled")
        
        # Reset PoE et macros nécessitent IP ET port
        self.reset_poe_btn.set_state("normal" if (has_ip and has_port) else "disabled")
        self.macro1_btn.set_state("normal" if (has_ip and has_port) else "disabled")
        self.macro2_btn.set_state("normal" if (has_ip and has_port) else "disabled")
        self.macro3_btn.set_state("normal" if (has_ip and has_port) else "disabled")
        
        controller = self.current_result.get("controller", "")
        self.controller_info_label.config(text=f"→ {controller}" if controller else "")

    # ==================== DATA LOADING ====================
    
    def load_all_data(self):
        self.ap_data = {}
        self.switch_ip_map = {}
        self.loaded_files = []

        switch_count = self.load_switch_ip_mapping()
        prime_count = self.load_prime_csvs()
        dna_rogue_count = self.load_dna_rogue_devices()
        wireless_count = self.load_wireless_info()

        if not self.loaded_files:
            self.status_icon.config(fg=COLORS["accent_red"])
            self.file_status_label.config(
                text="Aucune donnée trouvée. Utilisez 'Recharger' pour collecter les données.",
                fg=COLORS["accent_red"],
            )
        else:
            self.status_icon.config(fg=COLORS["accent_green"])
            self.file_status_label.config(
                text=f"{len(self.ap_data):,} AP • Prime: {prime_count} • DNA: {dna_rogue_count} • Wireless: {wireless_count} • Switches: {switch_count}",
                fg=COLORS["text_secondary"],
            )

    def load_switch_ip_mapping(self):
        if not os.path.isfile(self.report_sw_path):
            return 0
        
        count = 0
        try:
            with open(self.report_sw_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
                f.seek(0)
                delimiter = ";" if ";" in first_line else ","
                reader = csv.reader(f, delimiter=delimiter, quotechar='"')
                header = next(reader, None)
                if not header:
                    return 0
                
                hostname_idx = 1
                ip_idx = 8
                
                for row in reader:
                    if len(row) > max(hostname_idx, ip_idx):
                        hostname = row[hostname_idx].strip().strip('"')
                        ip_admin = row[ip_idx].strip().strip('"')
                        if hostname and ip_admin:
                            self.switch_ip_map[hostname] = ip_admin
                            self.switch_ip_map[hostname.upper()] = ip_admin
                            self.switch_ip_map[hostname.lower()] = ip_admin
                            count += 1
            
            if count > 0:
                self.loaded_files.append(self.report_sw_path)
        except Exception:
            pass
        return count

    def get_switch_ip(self, switch_hostname):
        if not switch_hostname:
            return ""
        if switch_hostname in self.switch_ip_map:
            return self.switch_ip_map[switch_hostname]
        if switch_hostname.upper() in self.switch_ip_map:
            return self.switch_ip_map[switch_hostname.upper()]
        for sw_name, sw_ip in self.switch_ip_map.items():
            if switch_hostname.upper() in sw_name.upper() or sw_name.upper() in switch_hostname.upper():
                return sw_ip
        return ""

    def get_latest_csv_in_dir(self, directory):
        try:
            if not os.path.isdir(directory):
                return None
            cands = [f for f in os.listdir(directory) if f.lower().endswith(".csv")]
            if not cands:
                return None
            cands.sort(key=lambda fn: os.path.getmtime(os.path.join(directory, fn)))
            return os.path.join(directory, cands[-1])
        except Exception:
            return None

    def get_preferred_txt_in_dir(self, directory, preferred_name):
        try:
            if not os.path.isdir(directory):
                return None
            preferred = os.path.join(directory, preferred_name)
            if os.path.isfile(preferred):
                return preferred
            cands = [os.path.join(directory, f) for f in os.listdir(directory) if f.lower().endswith(".txt")]
            if not cands:
                return None
            cands.sort(key=lambda p: os.path.getmtime(p))
            return cands[-1]
        except Exception:
            return None

    def parse_ap_inventory_from_file(self, path, source_label):
        rows = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return rows
        
        lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        i = 0
        while i < len(lines) and lines[i].strip() != "AP Inventory":
            i += 1
        if i >= len(lines):
            return rows
        i += 1
        while i < len(lines) and not lines[i].startswith("AP Name,"):
            i += 1
        if i >= len(lines):
            return rows
        
        header_line = lines[i]
        header_parts = next(csv.reader([header_line]))
        has_mac = len(header_parts) >= 6
        has_ip = len(header_parts) >= 7
        i += 1

        while i < len(lines) and lines[i].strip():
            try:
                row = next(csv.reader([lines[i]]))
                if len(row) >= 5:
                    entry = {
                        "AP Name": row[0].strip(),
                        "Neighbor Name": row[1].strip(),
                        "Neighbor Address": row[2].strip(),
                        "Neighbor Port": row[3].strip(),
                        "Controller Name": row[4].strip(),
                        "Source": source_label,
                    }
                    if has_mac and len(row) > 5:
                        entry["MAC Address"] = row[5].strip()
                    if has_ip and len(row) > 6:
                        entry["IP Address"] = row[6].strip()
                    rows.append(entry)
            except Exception:
                pass
            i += 1
        return rows

    def load_prime_csvs(self):
        total_rows = 0
        for idx, d in enumerate(self.csv_dirs, start=1):
            csv_path = self.get_latest_csv_in_dir(d)
            source = f"prime{idx}"
            if not csv_path:
                continue
            self.loaded_files.append(csv_path)
            rows = self.parse_ap_inventory_from_file(csv_path, source)
            total_rows += len(rows)
            for r in rows:
                ap = r.get("AP Name", "")
                if not ap:
                    continue
                new = {
                    "switch": r.get("Neighbor Name") or "",
                    "port": r.get("Neighbor Port") or "",
                    "neighbor_ip": r.get("Neighbor Address") or "",
                    "controller": r.get("Controller Name") or "",
                    "source": source,
                    "ap_location": "", "ap_profile": "", "rf_profile": "",
                    "site_tag": "", "policy_tag": "", "ap_group": "",
                    "management_ip": r.get("IP Address") or "",
                    "mac_address": r.get("MAC Address") or "",
                    "platform": "", "series": "",
                }
                self.merge_ap_entry(ap, new)
        return total_rows

    def load_dna_rogue_devices(self):
        added = 0
        for d in self.dna_dirs:
            path = self.get_preferred_txt_in_dir(d, self.default_dna_filename)
            if not path:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            idx = content.find("## Network Devices")
            if idx == -1:
                continue
            sub = content[idx:]
            s = sub.find("{")
            e = sub.rfind("}")
            if s == -1 or e == -1 or e <= s:
                continue
            blob = sub[s:e+1]
            try:
                payload = json.loads(blob)
            except Exception:
                m = re.search(r'"response"\s*:\s*(\[\s*.*\s*\])', blob, flags=re.DOTALL)
                if not m:
                    continue
                try:
                    payload = {"response": json.loads(m.group(1))}
                except Exception:
                    continue

            devices = []
            if isinstance(payload, dict) and isinstance(payload.get("response"), list):
                devices = payload["response"]
            elif isinstance(payload, list):
                devices = payload

            source_name = os.path.basename(d) or "dna"
            for dev in devices:
                if not isinstance(dev, dict):
                    continue
                hostname = (dev.get("hostname") or "").strip()
                if not hostname:
                    continue
                ctrl_ip = (dev.get("associatedWlcIp") or "").strip()
                controller = CONTROLLER_IP_TO_NAME.get(ctrl_ip, ctrl_ip)

                new = {
                    "switch": "", "port": "", "neighbor_ip": "",
                    "controller": controller or "",
                    "source": source_name,
                    "ap_location": (dev.get("snmpLocation") or "").strip(),
                    "ap_profile": "", "rf_profile": "", "site_tag": "", "policy_tag": "", "ap_group": "",
                    "management_ip": (dev.get("managementIpAddress") or "").strip(),
                    "mac_address": (dev.get("apEthernetMacAddress") or "").strip(),
                    "platform": (dev.get("platformId") or "").strip(),
                    "series": (dev.get("series") or "").strip(),
                }
                self.merge_ap_entry(hostname, new)
                added += 1

            self.loaded_files.append(path)
        return added

    def load_wireless_info(self):
        path = self.wireless_info_path
        if not os.path.isfile(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return 0

        arrays = self.extract_json_arrays(content)
        added = 0
        for arr in arrays:
            if not isinstance(arr, list):
                continue
            for entry in arr:
                if not isinstance(entry, dict) or entry.get("status") != 200:
                    continue
                dev = entry.get("device") or {}
                hostname = (dev.get("hostname") or "").strip()
                if not hostname:
                    continue

                data = entry.get("data") or {}
                response = data.get("response") if isinstance(data, dict) else {}
                if not isinstance(response, dict):
                    response = {}

                neighbor_str = self.find_cdp_neighbor(data)
                sw, port = self.parse_cdp_neighbor(neighbor_str)

                ctrl_ip = (dev.get("associatedWlcIp") or "").strip()
                controller = CONTROLLER_IP_TO_NAME.get(ctrl_ip, ctrl_ip)

                new = {
                    "switch": sw or "", "port": port or "", "neighbor_ip": "",
                    "controller": controller or "",
                    "source": "dna-wireless",
                    "ap_location": (response.get("apLocation") or "").strip(),
                    "ap_profile": (response.get("apProfileName") or "").strip(),
                    "rf_profile": (response.get("rfProfileName") or "").strip(),
                    "site_tag": (response.get("siteTagName") or "").strip(),
                    "policy_tag": (response.get("policyTagName") or "").strip(),
                    "ap_group": (response.get("apGroupName") or "").strip(),
                    "management_ip": (dev.get("managementIpAddress") or "").strip(),
                    "mac_address": (dev.get("apEthernetMacAddress") or response.get("ethMacAddress") or "").strip(),
                    "platform": (dev.get("platformId") or "").strip(),
                    "series": (dev.get("series") or "").strip(),
                }
                self.merge_ap_entry(hostname, new)
                added += 1

        if path not in self.loaded_files:
            self.loaded_files.append(path)
        return added

    def extract_json_arrays(self, content: str):
        arrays = []
        pos = 0
        while True:
            idx = content.find("# Count:", pos)
            if idx == -1:
                break
            start = content.find("[", idx)
            if start == -1:
                pos = idx + 7
                continue
            depth = 0
            in_str = False
            esc = False
            end = -1
            for i in range(start, len(content)):
                ch = content[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                else:
                    if ch == '"':
                        in_str = True
                    elif ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
            if end != -1:
                try:
                    arrays.append(json.loads(content[start:end+1]))
                except Exception:
                    pass
                pos = end + 1
            else:
                pos = start + 1
        return arrays

    def find_cdp_neighbor(self, data):
        if not isinstance(data, (dict, list)):
            return ""
        if isinstance(data, dict):
            if "response" in data:
                return self.find_cdp_neighbor(data["response"])
            for k, v in data.items():
                if k == "cdpNeighborDetails" and isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and item.strip():
                            return item.strip()
                if isinstance(v, (dict, list)):
                    s = self.find_cdp_neighbor(v)
                    if s:
                        return s
        elif isinstance(data, list):
            for it in data:
                s = self.find_cdp_neighbor(it)
                if s:
                    return s
        return ""

    def parse_cdp_neighbor(self, s: str):
        if not s:
            return "", ""
        m = re.match(r"^\s*(?P<sw>.+?)\s*\(\s*Port\s*:\s*(?P<port>[^)]+)\)\s*$", s)
        if m:
            return m.group("sw").strip(), m.group("port").strip()
        return "", ""

    def merge_ap_entry(self, ap_key: str, new: dict):
        cur = self.ap_data.get(ap_key)
        if not cur:
            self.ap_data[ap_key] = new
            return

        def score(d):
            s = 0
            if d.get("switch"): s += 2
            if d.get("port"): s += 2
            if d.get("controller"): s += 1
            if d.get("neighbor_ip"): s += 1
            if d.get("mac_address"): s += 1
            if d.get("ap_location") and d.get("ap_location") != "default location": s += 1
            return s

        if score(new) >= score(cur):
            merged = {}
            for k in set(cur.keys()) | set(new.keys()):
                new_val = new.get(k, "")
                cur_val = cur.get(k, "")
                if k == "ap_location":
                    if new_val and new_val != "default location":
                        merged[k] = new_val
                    elif cur_val and cur_val != "default location":
                        merged[k] = cur_val
                    else:
                        merged[k] = new_val or cur_val
                else:
                    merged[k] = new_val or cur_val
            self.ap_data[ap_key] = merged
        else:
            for k in new.keys():
                if not cur.get(k) and new.get(k):
                    if k == "ap_location" and new.get(k) == "default location":
                        continue
                    cur[k] = new[k]

    # ==================== SEARCH ====================
    
    def search_ap(self):
        if not self.ap_data:
            messagebox.showwarning("Attention", "Aucune donnée chargée. Utilisez 'Recharger' pour collecter les données.")
            return
        ap_name = self.entry_ap.get().strip()
        if not ap_name:
            messagebox.showwarning("Attention", "Veuillez entrer un nom/hostname")
            return

        self.current_result = {"switch_ip": "", "mac": "", "controller": "", "ap_name": "", "port": "", "switch": ""}
        self.update_action_buttons()

        if ap_name in self.ap_data:
            self.show_result_for(ap_name, self.ap_data[ap_name])
            return

        ap_l = ap_name.lower()
        matches = [k for k in self.ap_data.keys() if ap_l in k.lower()]
        if matches:
            matches.sort()
            out = [f"'{ap_name}' non trouvé exactement.\n\nCorrespondances ({len(matches)}):"]
            for m in matches[:15]:
                info = self.ap_data[m]
                sw = info.get("switch") or ""
                port = info.get("port") or ""
                ctrl = info.get("controller") or ""
                sw_ip = self.get_switch_ip(sw) if sw else ""
                if sw and port:
                    if sw_ip:
                        out.append(f"• {m} → {sw} ({sw_ip}) port {port} [{ctrl}]")
                    else:
                        out.append(f"• {m} → {sw} port {port} [{ctrl}]")
                elif ctrl:
                    out.append(f"• {m} → [{ctrl}]")
                else:
                    out.append(f"• {m}")
            if len(matches) > 15:
                out.append(f"... et {len(matches) - 15} autres")
            self.display_result("\n".join(out), success=False)
        else:
            self.display_result(f"Aucune borne trouvée pour '{ap_name}'", success=False)

    def show_result_for(self, ap_name, info):
        sw = info.get("switch") or ""
        port = info.get("port") or ""
        neighbor_ip = info.get("neighbor_ip") or ""
        ctrl = info.get("controller") or ""
        switch_ip = self.get_switch_ip(sw) if sw else ""
        
        mgmt_ip = info.get("management_ip") or ""
        mac = info.get("mac_address") or ""
        platform = info.get("platform") or ""
        ap_location = info.get("ap_location") or ""

        self.current_result = {
            "switch_ip": switch_ip or neighbor_ip,
            "mac": mac,
            "controller": ctrl,
            "ap_name": ap_name,
            "port": port,
            "switch": sw,
        }
        self.update_action_buttons()

        lines = []
        if sw and port:
            if switch_ip:
                lines.append(f"borne : {ap_name}\nport : {port}\nswitch : {sw} (IP {switch_ip})")
            elif neighbor_ip:
                lines.append(f"borne : {ap_name}\nport : {port}\nswitch : {sw} (IP {neighbor_ip})")
            else:
                lines.append(f"borne : {ap_name}\nport : {port}\nswitch : {sw}")
        else:
            lines.append(f"Borne wifi: {ap_name}")
        
        if ctrl:
            lines.append(f"Contrôleur: {ctrl}")
        
        details = []
        if mgmt_ip:
            details.append(f"IP Management AP: {mgmt_ip}")
        if mac:
            details.append(f"MAC: {mac}")
        if platform:
            details.append(f"Plateforme: {platform}")
        if ap_location and ap_location != "default location":
            details.append(f"Location: {ap_location}")
        
        if details:
            lines.append("")
            lines.append("─" * 40)
            for d in details:
                lines.append(f"  • {d}")
        
        lines.append("")
        lines.append(f"[Source: {info.get('source', '')}]")

        self.display_result("\n".join(lines), success=True)
        
        ip_to_show = switch_ip or neighbor_ip
        if sw and port:
            if ip_to_show:
                clip = f"borne : {ap_name} \nport : {port} \nswitch : {sw} (IP {ip_to_show}) \ncontrôleur : {ctrl}"
            else:
                clip = f"borne : {ap_name} \nport : {port} \nswitch : {sw} \ncontrôleur : {ctrl}"
        else:
            clip = f"borne : {ap_name} \ncontrôleur : {ctrl}\n" if ctrl else f"borne : {ap_name}"
        self.copy_to_clipboard_text(clip)
        self.show_copy_status("✓ Copié")

    # ==================== DISPLAY ====================
    
    def display_result(self, text, success=True):
        self.last_result = text
        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(1.0, text)
        self.result_text.config(fg=COLORS["accent_green"] if success else COLORS["accent_orange"])
        self.result_text.config(state="disabled")
        self.copy_btn.set_state("normal")

    def copy_to_clipboard(self):
        if self.last_result:
            self.copy_to_clipboard_text(self.last_result)
            self.show_copy_status("✓ Tout copié")

    def clear_fields(self):
        self.entry_ap.delete(0, tk.END)
        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state="disabled")
        self.copy_btn.set_state("disabled")
        self.copy_status_label.config(text="")
        self.last_result = ""
        self.current_result = {"switch_ip": "", "mac": "", "controller": "", "ap_name": "", "port": "", "switch": ""}
        self.update_action_buttons()

    
    def display_macro_result(self, success, macro_name, ap_name, switch_name, switch_ip, port, log_content):
        """Affiche le résultat d'une macro"""
        lines = []
        
        if success:
            lines.append("=" * 50)
            lines.append(f"✓ {macro_name.upper()} TERMINÉ")
            lines.append("=" * 50)
        else:
            lines.append("=" * 50)
            lines.append(f"❌ {macro_name.upper()} ÉCHOUÉ")
            lines.append("=" * 50)
        
        lines.append("")
        lines.append(f"Borne: {ap_name}")
        lines.append(f"Switch: {switch_name} ({switch_ip})")
        lines.append(f"Interface: {port}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        if log_content:
            lines.append("─" * 50)
            lines.append("DÉTAIL:")
            lines.append("─" * 50)
            for line in log_content.split('\n'):
                if '] ' in line and line.startswith('['):
                    line = line.split('] ', 1)[1] if len(line.split('] ', 1)) > 1 else line
                if line.strip():
                    lines.append(line)
        
        self.display_result("\n".join(lines), success=success)
    def set_ui_busy(self, busy: bool):
        try:
            self.window.config(cursor="watch" if busy else "")
            self.search_btn.set_state("disabled" if busy else "normal")
            self.clear_btn.set_state("disabled" if busy else "normal")
            self.copy_btn.set_state("disabled" if busy else "normal")
            self.refresh_btn.set_state("disabled" if busy else "normal")
            self.reset_poe_btn.set_state("disabled" if busy else "normal")
            self.window.update_idletasks()
            self.macro1_btn.set_state("disabled" if busy else "normal")
            self.macro2_btn.set_state("disabled" if busy else "normal")
            self.macro3_btn.set_state("disabled" if busy else "normal")
        except Exception:
            pass

    # ==================== RELOAD DIALOG ====================
    
    def open_reload_dialog(self):
        dlg = tk.Toplevel(self.window)
        dlg.title("Recharger les données")
        dlg.configure(bg=COLORS["bg_medium"])
        dlg.grab_set()
        dlg.resizable(False, False)

        pad = {"padx": 14, "pady": 8}

        tk.Label(dlg, text="Identifiants DNA Center", font=("Segoe UI", 11, "bold"),
                 bg=COLORS["bg_medium"], fg=COLORS["text_primary"]).grid(row=0, column=0, columnspan=2, **pad, sticky="w")
        tk.Label(dlg, text="Utilisateur:", bg=COLORS["bg_medium"], fg=COLORS["text_secondary"]).grid(row=1, column=0, **pad, sticky="e")
        tk.Label(dlg, text="Mot de passe:", bg=COLORS["bg_medium"], fg=COLORS["text_secondary"]).grid(row=2, column=0, **pad, sticky="e")

        dna_user_var = tk.StringVar()
        dna_pwd_var = tk.StringVar()
        tk.Entry(dlg, textvariable=dna_user_var, width=28, bg=COLORS["bg_input"], fg=COLORS["text_primary"], relief="flat").grid(row=1, column=1, **pad)
        tk.Entry(dlg, textvariable=dna_pwd_var, width=28, bg=COLORS["bg_input"], fg=COLORS["text_primary"], relief="flat", show="*").grid(row=2, column=1, **pad)

        tk.Label(dlg, text="Identifiants Prime", font=("Segoe UI", 11, "bold"),
                 bg=COLORS["bg_medium"], fg=COLORS["text_primary"]).grid(row=3, column=0, columnspan=2, **pad, sticky="w")
        tk.Label(dlg, text="Utilisateur:", bg=COLORS["bg_medium"], fg=COLORS["text_secondary"]).grid(row=4, column=0, **pad, sticky="e")
        tk.Label(dlg, text="Mot de passe:", bg=COLORS["bg_medium"], fg=COLORS["text_secondary"]).grid(row=5, column=0, **pad, sticky="e")

        prime_user_var = tk.StringVar()
        prime_pwd_var = tk.StringVar()
        tk.Entry(dlg, textvariable=prime_user_var, width=28, bg=COLORS["bg_input"], fg=COLORS["text_primary"], relief="flat").grid(row=4, column=1, **pad)
        tk.Entry(dlg, textvariable=prime_pwd_var, width=28, bg=COLORS["bg_input"], fg=COLORS["text_primary"], relief="flat", show="*").grid(row=5, column=1, **pad)

        tk.Label(dlg, text="Workers:", bg=COLORS["bg_medium"], fg=COLORS["text_secondary"]).grid(row=6, column=0, **pad, sticky="e")
        workers_var = tk.StringVar(value="10")
        tk.Entry(dlg, textvariable=workers_var, width=8, bg=COLORS["bg_input"], fg=COLORS["text_primary"], relief="flat").grid(row=6, column=1, **pad, sticky="w")

        btn_frame = tk.Frame(dlg, bg=COLORS["bg_medium"])
        btn_frame.grid(row=7, column=0, columnspan=2, pady=(10, 12))

        def on_submit():
            dna_user = dna_user_var.get().strip()
            dna_pwd = dna_pwd_var.get()
            prime_user = prime_user_var.get().strip()
            prime_pwd = prime_pwd_var.get()
            workers = int(workers_var.get().strip() or "10")
            dlg.destroy()
            self.run_data_collection(dna_user, dna_pwd, prime_user, prime_pwd, workers)

        ModernButton(btn_frame, text="Annuler", command=dlg.destroy,
                     bg_color=COLORS["accent_gray"], hover_color=COLORS["accent_gray_hover"],
                     width=100, height=34).pack(side="left", padx=6)
        ModernButton(btn_frame, text="Lancer", command=on_submit,
                     bg_color=COLORS["accent_blue"], hover_color=COLORS["accent_blue_hover"],
                     width=100, height=34).pack(side="left", padx=6)

        self.window.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - 200
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - 150
        dlg.geometry(f"+{x}+{y}")

    def run_data_collection(self, dna_user, dna_pwd, prime_user, prime_pwd, workers=10):
        self.set_ui_busy(True)
        self.file_status_label.config(text="Collecte en cours...", fg=COLORS["text_secondary"])

        def progress_cb(done, total):
            try:
                self.window.after(0, lambda: self.file_status_label.config(
                    text=f"Wireless-info: {done}/{total}...", fg=COLORS["text_secondary"]))
            except Exception:
                pass

        def worker():
            msgs = []
            
            if dna_user and dna_pwd:
                self.window.after(0, lambda: self.file_status_label.config(text="Collecte DNA...", fg=COLORS["text_secondary"]))
                ok, msg = run_dna_collection(dna_user, dna_pwd, workers, progress_cb)
                msgs.append(msg)
            else:
                msgs.append("DNA: Ignoré (pas de credentials)")
            
            if prime_user and prime_pwd:
                self.window.after(0, lambda: self.file_status_label.config(text="Collecte Prime...", fg=COLORS["text_secondary"]))
                ok, msg = run_prime_collection(prime_user, prime_pwd)
                msgs.append(msg)
            else:
                msgs.append("Prime: Ignoré (pas de credentials)")
            
            def finalize():
                self.set_ui_busy(False)
                self.load_all_data()
                messagebox.showinfo("Collecte terminée", "\n".join(msgs))
            
            self.window.after(0, finalize)

        threading.Thread(target=worker, daemon=True).start()


# ================================================================================
# MAIN
# ================================================================================

if __name__ == "__main__":
    app = WiFiAPFinder()
    app.run()