import requests
import base64
import hashlib
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ==========================================
def get_firebase_base_url():
    print("🔵 [Auto] Fetching Dynamic URL from Firebase...")
    url = "https://firebaseremoteconfig.googleapis.com/v1/projects/963020218535/namespaces/firebase:fetch"
    
    headers = {
        "accept": "application/json",
        "x-android-package": "com.cricfy.tv",
        "x-goog-api-key": "AIzaSyAh9jkEU0E_UYxH0m_BKAt-uUSTiTPqhb8",
        "content-type": "application/json; charset=utf-8",
        "user-agent": "okhttp/5.0.0-alpha.12"
    }
    
    payload = {
        "appInstanceId": "e368b85dbdd148bdb73f1c5fecfdd3e2",
        "appInstanceIdToken": "",
        "appId": "1:963020218535:android:47ec53252c64fb3c9c7b82",
        "countryCode": "US",
        "languageCode": "en-US",
        "platformVersion": "30",
        "timeZone": "UTC",
        "appVersion": "5.0",
        "appBuild": "50",
        "packageName": "com.cricfy.tv",
        "sdkVersion": "22.1.0",
        "analyticsUserProperties": {}
    }
    
    try:
        res = requests.post(url, headers=headers, json=payload, timeout=10)
        if res.status_code == 200:
            data = res.json()
            entries = data.get("entries", {})
            
            # Dono URLs nikal liye
            url1 = entries.get("cric_api1")
            url2 = entries.get("cric_api2")
            
            # Active Link Checker (Jo zinda hoga wahi return karega)
            for api_url in [url1, url2]:
                if api_url:
                    clean_url = api_url.rstrip("/")
                    print(f"   🔄 Checking URL: {clean_url} ...")
                    try:
                        # 3 second timeout ke sath check karega ki site chal rahi hai ya nahi
                        requests.get(clean_url, timeout=3)
                        print(f"   🎉 SUCCESS! Active Auto-URL Detected: {clean_url}")
                        return clean_url
                    except requests.exceptions.RequestException:
                        print(f"   ⚠️ URL {clean_url} is dead/blocked. Trying next...")
                        continue # Pehla fail hua to loop dusre par jayega
                        
    except Exception as e:
        print(f"   ❌ Firebase Error: {e}")
        
    print("   ⚠️ Fetch failed or all URLs dead. Using fallback URL.")
    # Fallback ko abhi working wale pe set kar diya hai just in case
    return "https://cfykskgdjk100.top"

# --- CONFIGURATION ---
# Base URL is resolved directly from Firebase.
BASE_URL = get_firebase_base_url()
OUTPUT_FILE = Path(__file__).resolve().with_name("playlist.m3u")
WIB_TIMEZONE = timezone(timedelta(hours=7), name="WIB")

# Built-in fallback pairs reconstructed from libnative-lib.so in dex.
# These values are raw 16-byte AES key/IV pairs, not hex strings.
APK_FALLBACK_KEYS = (
    (b"3hHzxYAgSGI8/ham", b"UqCvkvjecEIz842V"),
    (b"MqeYGCT4AYKoHKrT", b"oHKrTQuPx8zl8oJ+"),
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Referer": f"{BASE_URL}/",
    "Origin": BASE_URL,
    "Connection": "keep-alive"
}

# --- HELPER FUNCTIONS ---

def _valid_json_text(value):
    """Only accept decrypted payloads that are valid category/channel JSON."""
    if not value:
        return None

    candidate = value.lstrip("\ufeff \t\r\n")
    if not candidate.startswith(("[", "{")):
        return None

    try:
        json.loads(candidate)
        return candidate
    except (ValueError, TypeError):
        return None


def _decrypt_apk_v71(clean_b64):
    """Mirror com.android.vending.networking.Baker.merge from the APK in dex."""
    try:
        padded_b64 = clean_b64 + ("=" * (-len(clean_b64) % 4))
        packed = base64.b64decode(padded_b64, validate=True)

        # Baker stores a 16-byte seed before the masked AES ciphertext.
        if len(packed) < 32 or (len(packed) - 16) % AES.block_size:
            return None

        seed = packed[:16]
        masked_ciphertext = packed[16:]

        mask = bytearray()
        counter = 0
        while len(mask) < len(masked_ciphertext):
            mask.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
            counter += 1

        ciphertext = bytes(
            value ^ mask[index]
            for index, value in enumerate(masked_ciphertext)
        )

        key_material = hashlib.sha256(seed).digest()
        cipher = AES.new(
            key_material[:16],
            AES.MODE_CBC,
            key_material[16:32],
        )
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return _valid_json_text(plaintext.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError):
        return None


def _decrypt_apk_fallback(clean_b64):
    """Try the two fallback AES pairs embedded in the APK native library."""
    padded_b64 = clean_b64 + ("=" * (-len(clean_b64) % 4))
    try:
        ciphertext = base64.b64decode(padded_b64, validate=True)
    except (ValueError, TypeError):
        return None

    for key, iv in APK_FALLBACK_KEYS:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            decoded = _valid_json_text(plaintext.decode("utf-8"))
            if decoded:
                return decoded
        except (ValueError, TypeError, UnicodeError):
            continue
    return None


def decrypt_data(encrypted_text):
    if not encrypted_text:
        return None

    clean_b64 = "".join(encrypted_text.split())

    # Both formats are self-contained; no environment variables are required.
    decrypted = _decrypt_apk_v71(clean_b64)
    if decrypted:
        return decrypted

    return _decrypt_apk_fallback(clean_b64)

def convert_utc_to_wib(utc_time_str):
    try:
        if not utc_time_str:
            return ""
        utc_dt = datetime.strptime(utc_time_str, "%Y/%m/%d %H:%M:%S %z")
        return utc_dt.astimezone(WIB_TIMEZONE).strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return ""


def get_event_status(event, now_utc=None):
    """Return LIVE, UPCOMING, or ENDED from the event's UTC schedule."""
    event_info = event.get("eventInfo", {})
    start_value = event_info.get("startTime", "")
    end_value = event_info.get("endTime", "")

    try:
        start_time = datetime.strptime(start_value, "%Y/%m/%d %H:%M:%S %z")
        end_time = datetime.strptime(end_value, "%Y/%m/%d %H:%M:%S %z")
        current_time = now_utc or datetime.now(timezone.utc)

        if start_time <= current_time <= end_time:
            return "LIVE"
        if current_time < start_time:
            return "UPCOMING"
        return "ENDED"
    except (TypeError, ValueError):
        return "UNKNOWN"

def get_smart_filename(event):
    guesses = []
    
    # 1. Event ID
    eid = str(event.get('id', ''))
    if eid:
        guesses.append(eid)
        guesses.append(f"match-{eid}")
    
    # 2. Slug & Title (FORCE LOWERCASE FIX HERE)
    # Humne .lower() laga diya hai taaki 'ICC' ban jaye 'icc'
    slug = event.get('slug', '').strip().lower()
    
    if slug:
        # A. Normal Slug
        guesses.append(slug) 
        guesses.append(urllib.parse.quote(slug)) 
        guesses.append(slug.replace(" ", "-")) 
        
        # B. Numbered Variations (1 to 6)
        for i in range(1, 7):
            # Try: "icc t20 world cup 1" -> "icc%20t20...%201.txt"
            guesses.append(urllib.parse.quote(f"{slug} {i}"))
            
            # Try: "icc-t20-world-cup-1.txt"
            guesses.append(f"{slug.replace(' ', '-')}-{i}")
    
    # 3. Team Names (Also Lowercase)
    team_a = event.get('eventInfo', {}).get('teamA', '').strip().lower()
    team_b = event.get('eventInfo', {}).get('teamB', '').strip().lower()
    
    if team_a and team_b:
        t_a = team_a.replace(" ", "")
        t_b = team_b.replace(" ", "")
        base_vs = f"{t_a}-vs-{t_b}"
        guesses.append(base_vs)
        
        for i in range(1, 4):
            guesses.append(f"{base_vs}-{i}")
        
    return guesses


def format_drm_key(drm_key):
    """Keep ClearKey JSON on one line so the M3U entry remains valid."""
    value = str(drm_key).strip()
    if value.startswith("{"):
        try:
            return json.dumps(json.loads(value), separators=(",", ":"))
        except (TypeError, ValueError):
            pass
    return value

def fetch_match_streams(event, status):
    entries = []
    title = event.get('title', 'Sports Event')
    event_info = event.get('eventInfo', {})
    logo = event_info.get('eventLogo', '')
    wib_time = convert_utc_to_wib(event_info.get('startTime', ''))
    sport = event_info.get('eventCat', 'Other')
    team_a = str(event_info.get('teamA', '')).strip()
    team_b = str(event_info.get('teamB', '')).strip()
    matchup = f"{team_a} vs {team_b}" if team_a and team_b else title
    time_label = f"[{wib_time} WIB]" if wib_time else ""
    display_title = f"[{status}]{time_label} {matchup}"

    print(f"   🏟️ Processing: {display_title} | {sport}")

    valid_data = None
    filenames = get_smart_filename(event)
    
    for fname in filenames:
        try:
            for ext in [".txt", ""]:
                url = f"{BASE_URL}/channels/{fname}{ext}"
                res = requests.get(url, headers=HEADERS, timeout=3)
                if res.status_code == 200 and "google.com" not in res.text and len(res.text) > 50:
                    valid_data = decrypt_data(res.text)
                    if valid_data: 
                        print(f"      ✅ FOUND: {fname}{ext}")
                        break
            if valid_data: break
        except:
            continue

    if not valid_data:
        print("      ❌ No stream file found.")
        return []

    try:
        data = json.loads(valid_data)
        streams = data.get('streamUrls', [])
        
        for s in streams:
            stream_name = s.get('title', 'Link')
            raw_link = s.get('link', '')
            final_url = raw_link

            entry = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{sport}", {display_title} ({stream_name})\n'
            drm_key = s.get('api')
            if drm_key:
                entry += '#KODIPROP:inputstream.adaptive.license_type=clearkey\n'
                entry += f'#KODIPROP:inputstream.adaptive.license_key={format_drm_key(drm_key)}\n'
            entry += f'{final_url}\n'
            entries.append(entry)

    except Exception as e:
        print(f"      ⚠️ JSON Error: {e}")

    return entries


def fetch_sport_channels():
    """Append the app's regular Sports channels after all event streams."""
    entries = []
    print("📺 Fetching regular Sports channels...")

    try:
        response = requests.get(
            f"{BASE_URL}/categories/sports.txt",
            headers=HEADERS,
            timeout=15,
        )
        if response.status_code != 200:
            print(f"   ❌ Failed to fetch Sports category: {response.status_code}")
            return entries

        raw_data = decrypt_data(response.text)
        if not raw_data:
            print("   ❌ Sports category decryption failed.")
            return entries

        channels = json.loads(raw_data)
    except (requests.RequestException, TypeError, ValueError) as error:
        print(f"   ❌ Sports category error: {error}")
        return entries

    published_channels = [
        channel
        for channel in channels
        if str(channel.get("publish", "1")) == "1"
    ]

    def fetch_one_channel(index, channel):
        channel_entries = []
        slug = str(channel.get("slug", "")).strip().lower()
        channel_id = str(channel.get("id", "")).strip()
        channel_name = str(channel.get("title") or slug or "Sports").strip()
        logo = str(channel.get("image", "")).strip()

        filenames = []
        for candidate in (slug, urllib.parse.quote(slug), channel_id):
            if candidate and candidate not in filenames:
                filenames.append(candidate)

        channel_data = None
        found_name = None
        for filename in filenames:
            try:
                response = requests.get(
                    f"{BASE_URL}/channels/{filename}.txt",
                    headers=HEADERS,
                    timeout=5,
                )
                if response.status_code != 200 or len(response.text) <= 50:
                    continue
                channel_data = decrypt_data(response.text)
                if channel_data:
                    found_name = f"{filename}.txt"
                    break
            except requests.RequestException:
                continue

        if not channel_data:
            return index, channel_entries, f"❌ [SPORT] No stream file: {channel_name}"

        try:
            streams = json.loads(channel_data).get("streamUrls", [])
        except (TypeError, ValueError):
            return index, channel_entries, f"❌ [SPORT] Invalid JSON: {channel_name}"

        added = 0
        for stream in streams:
            stream_name = str(stream.get("title", "Link")).strip()
            stream_url = str(stream.get("link", "")).strip()
            if not stream_url:
                continue

            display_title = f"[SPORT] {channel_name} | {stream_name}"
            entry = (
                f'#EXTINF:-1 tvg-logo="{logo}" group-title="Sports", '
                f'{display_title}\n'
            )
            drm_key = stream.get("api")
            if drm_key:
                entry += '#KODIPROP:inputstream.adaptive.license_type=clearkey\n'
                entry += (
                    '#KODIPROP:inputstream.adaptive.license_key='
                    f'{format_drm_key(drm_key)}\n'
                )
            entry += f"{stream_url}\n"
            channel_entries.append(entry)
            added += 1

        message = f"✅ [SPORT] {channel_name}: {added} streams ({found_name})"
        return index, channel_entries, message

    ordered_results = {}
    failed_indices = []
    worker_count = min(6, max(1, len(published_channels)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(fetch_one_channel, index, channel)
            for index, channel in enumerate(published_channels)
        ]
        for future in as_completed(futures):
            try:
                index, channel_entries, message = future.result()
            except Exception as error:
                print(f"   ❌ [SPORT] Worker error: {error}")
                continue
            ordered_results[index] = channel_entries
            if not channel_entries:
                failed_indices.append(index)
            print(f"   {message}")

    # The server may throttle concurrent requests. Retry misses sequentially
    # after the worker pool is closed so valid channels are not discarded.
    if failed_indices:
        print(f"🔄 Retrying {len(failed_indices)} Sports groups sequentially...")
        for index in failed_indices:
            _, channel_entries, message = fetch_one_channel(
                index,
                published_channels[index],
            )
            ordered_results[index] = channel_entries
            print(f"   {message}")

    for index in range(len(published_channels)):
        entries.extend(ordered_results.get(index, []))

    print(
        f"📺 Sports channels: {len(published_channels)} groups, "
        f"{len(entries)} streams"
    )
    return entries

def main():
    print("🚀 Starting Standalone Generator (All Sports: Live + Upcoming)...")
    all_entries = []
    
    try:
        if not BASE_URL:
            print("❌ Error: CRIC base URL is missing.")
            return

        res = requests.get(f"{BASE_URL}/categories/live-events.txt", headers=HEADERS, timeout=15)
        if res.status_code != 200:
            print(f"❌ Failed to fetch categories: {res.status_code}")
            return
            
        raw_data = decrypt_data(res.text)
        if not raw_data:
            print("❌ Category Decryption Failed (no APK format matched)")
            return

        events = json.loads(raw_data)
        live_events = []
        upcoming_events = []
        now_utc = datetime.now(timezone.utc)

        for event in events:
            if str(event.get('publish', '1')) != '1':
                continue

            status = get_event_status(event, now_utc)
            if status == "LIVE":
                live_events.append(event)
            elif status == "UPCOMING":
                upcoming_events.append(event)

        print(f"📊 Events: {len(live_events)} live, {len(upcoming_events)} upcoming")

        for status, selected_events in (
            ("LIVE", live_events),
            ("UPCOMING", upcoming_events),
        ):
            for event in selected_events:
                match_entries = fetch_match_streams(event, status)
                all_entries.extend(match_entries)

        # Keep regular Sports channels in their own final playlist section.
        sport_entries = fetch_sport_channels()
        all_entries.extend(sport_entries)

        timestamp = datetime.now(WIB_TIMEZONE).strftime('%Y-%m-%d %H:%M WIB')
        
        with OUTPUT_FILE.open("w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            f.write(f"# UPDATED: {timestamp}\n\n")
            for entry in all_entries:
                f.write(entry)
        
        print(
            f"🎉 Playlist Updated! {len(all_entries)} streams "
            f"({len(sport_entries)} [SPORT]): {OUTPUT_FILE}"
        )

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
