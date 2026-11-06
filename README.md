# Microsoft Sentinel SIEM — Geo Map 1: Global Auth

Part of a broader **Microsoft Sentinel SIEM** portfolio series. This workbook visualizes the geographic origin of remote logon attempts, surfacing the classic SOC red flag: a successful login from a country the organization doesn't operate in.

## Platforms and Languages Leveraged

- Microsoft Sentinel / Log Analytics Workspace
- Microsoft Defender for Endpoint (`DeviceLogonEvents` table)
- Kusto Query Language (KQL)
- Azure Monitor Workbooks (native `geo_info_from_ip_address()` geolocation, MaxMind GeoLite2 data)

## Scenario

Remote logons — RDP and network authentication reaching in from the public internet — are one of the highest-signal places to watch in a SOC. A single successful logon from an unexpected country can mean a compromised credential is already in use. This workbook gives an analyst a fast, visual way to answer: **where are our remote logons coming from, and which of them succeeded?**

## What the Workbook Does

- **Time range parameter** — a pill selector (1hr / 4hr / 12hr / 1day / 7day / 30day) that drives every query in the workbook.
- **Bubble map** — plots each unique source IP by geolocation. Bubble **size** = total logon attempts from that source; **color** (green → red) = number of successful logons. The dangerous signal is a red/large bubble sitting somewhere the business has no footprint.
- **Companion table** — the same aggregation as a sortable grid (ranked by successes, then attempts), including the distinct accounts and devices each source IP touched.

## Query Logic

Both visuals query `DeviceLogonEvents` and apply the same core filters before aggregating:

- `RemoteIPType == "Public"` — excludes internal/private-range logons, which have no coordinates to plot and would just add noise.
- `LogonType in ("Network", "RemoteInteractive")` — scopes to remote network logons and RDP, the two logon types that can originate from an external attacker.
- `geo_info_from_ip_address()` — enriches each `RemoteIP` with country, city, and lat/long.
- Rows with unresolved geolocation are dropped (nothing to plot).
- Results are aggregated **per source IP** into: total attempts, successes, failures, distinct target devices, and up to 25 account names — so one bubble/row represents everything a single source did in the selected window.

```kql
DeviceLogonEvents
| where Timestamp {TimeRange}
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
| where LogonType in ("Network", "RemoteInteractive")
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         City      = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize Attempts        = count(),
            Successes       = countif(ActionType == "LogonSuccess"),
            Failures        = countif(ActionType == "LogonFailed"),
            TargetedDevices = dcount(DeviceName),
            Accounts        = make_set(AccountName, 25)
         by RemoteIP, Country, City, Latitude, Longitude
| extend MapLabel = strcat(RemoteIP, " (", Country, ") — ", Successes, " success / ", Attempts, " total")
| project Latitude, Longitude, MapLabel, Attempts, Successes, Failures, TargetedDevices, RemoteIP, Country, City, Accounts
| order by Successes desc, Attempts desc
```

> Geo data (MaxMind GeoLite2) is approximate — read the map as regions, not pinpoints.

![Inbound Authentication Origins map](./Inbound%20Authentication%20Origins.png)

## How to Use

1. Open **Microsoft Sentinel** → **Workbooks** → **Add workbook** → **Advanced Editor** (`</>` icon).
2. Delete the placeholder JSON and paste in the contents of [`workbook.json`](./workbook.json).
3. Update `crossComponentResources` and the `context.ownerId` field to point at your own Log Analytics workspace resource ID.
4. Save, then apply the workbook to your workspace.
5. Adjust the **Time range** pill at the top to control the lookback window for both the map and the table.

## Repository Contents

| File | Description |
|---|---|
| [`workbook.json`](./workbook.json) | Full Azure Monitor Workbook definition — import directly into Sentinel |

## About

Built as a lab exercise against a Log Analytics workspace (`LAW-Cyber-Range`). Part of a growing Microsoft Sentinel SIEM workbook series covering inbound authentication, outbound connections, data exfiltration indicators, inbound threat intel correlation, and threat intelligence ingestion (manual + Microsoft feed).
