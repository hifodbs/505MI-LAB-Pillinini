import requests
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os
import time

EPSS_URL = "https://api.first.org/data/v1/epss"
OUTPUT_DIR = "epss_csv"


def get_epss_for_date(cve_id: str, date: str):
    """
    Get EPSS score for a CVE on a specific date.
    Includes retry logic for unstable API responses.
    """
    params = {"cve": cve_id, "date": date}

    for attempt in range(3):
        try:
            r = requests.get(EPSS_URL, params=params, timeout=10)
            r.raise_for_status()
            data = r.json().get("data", [])

            if not data:
                return None

            return {
                "date": date,
                "cve": cve_id,
                "epss": float(data[0]["epss"]),
                "percentile": float(data[0]["percentile"]),
            }

        except Exception:
            if attempt == 2:
                return None
            time.sleep(1)

    return None


def fetch_epss_timeseries(cve_id: str, days: int = 60):
    """
    Query EPSS for each date individually and return a DataFrame.
    """
    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=days)

    results = []

    for i in range(days + 1):
        day = start_date + timedelta(days=i)
        day_str = day.strftime("%Y-%m-%d")

        entry = get_epss_for_date(cve_id, day_str)
        if entry:
            results.append(entry)

    return pd.DataFrame(results)


def save_cve_csv(cve_id: str, days: int = 60):
    """
    Fetch a CVE's EPSS timeseries and save to CSV.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    outfile = os.path.join(OUTPUT_DIR, f"{cve_id}.csv")

    df = fetch_epss_timeseries(cve_id, days)
    if df.empty:
        print(f"[WARN] No EPSS data found for {cve_id}")
        return

    df.to_csv(outfile, index=False)
    print(f"[OK] Saved {outfile}")


def plot_from_csv(cve_list):
    """
    Load all CVE CSVs and plot them.
    """
    plt.figure(figsize=(12, 6))

    for cve in cve_list:
        file_path = os.path.join(OUTPUT_DIR, f"{cve}.csv")

        if not os.path.exists(file_path):
            print(f"[SKIP] No CSV for {cve}")
            continue

        df = pd.read_csv(file_path)
        df["date"] = pd.to_datetime(df["date"])
        df = df.sort_values("date")

        plt.plot(df["date"], df["epss"], linewidth=2, label=cve)

    plt.title("EPSS Trends for CVEs (from saved CSV files)")
    plt.xlabel("Date")
    plt.ylabel("EPSS Score")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    cves = [
        "CVE-2025-55118",
        "CVE-2025-57644",
        "CVE-2025-10773",
        "CVE-2025-11032",
        "CVE-2025-11033",
        "CVE-2025-11035",
        "CVE-2025-10768",
        "CVE-2025-10769",
        "CVE-2025-10771",
        "CVE-2025-10597",
    ]

    days = 60

    # Step 1: save each CVE to CSV
    for cve in cves:
        save_cve_csv(cve, days)

    # Step 2: plot from the saved CSV files
    plot_from_csv(cves)
