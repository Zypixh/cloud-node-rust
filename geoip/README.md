# GeoIP 数据库 / GeoIP Databases

本目录是安装脚本使用的 GeoLite2 数据库唯一来源。
This directory is the canonical GeoIP source used by the installer.

| 文件 File | 内容 Content |
|---|---|
| `GeoLite2-City.mmdb` | MaxMind GeoLite2 城市库 City database |
| `GeoLite2-ASN.mmdb` | MaxMind GeoLite2 ASN 库 ASN database |
| `GeoLite2-Country.mmdb` | MaxMind GeoLite2 国家库 Country database |
| `SHA256SUMS.txt` | 上述文件的 SHA256 校验和；安装器下载后验签 Checksums verified by the installer |

## 来源 Provenance

快照来自 `P3TERX/GeoLite.mmdb`（MaxMind GeoLite2 镜像）。
Snapshot mirrored from `P3TERX/GeoLite.mmdb` (MaxMind GeoLite2).

## 更新 Updating

更新由仓库维护者手动决定，不会自动同步：
Updates are manual and controlled by the repository owner; nothing syncs automatically.

```bash
cd geoip
for f in GeoLite2-City.mmdb GeoLite2-ASN.mmdb GeoLite2-Country.mmdb; do
  curl -fsSL --retry 3 -o "$f" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/$f"
done
shasum -a 256 *.mmdb > SHA256SUMS.txt   # Linux: sha256sum *.mmdb > SHA256SUMS.txt
git add geoip/ && git commit -m "geoip: update GeoLite2 databases"
```

安装脚本默认从 `https://github.com/<repo>/raw/main/geoip/<file>` 下载；
`GEOIP_BASE_URL` 环境变量可指向其他镜像（需同样提供 `SHA256SUMS.txt`）。
The installer downloads from `https://github.com/<repo>/raw/main/geoip/<file>` by
default; set `GEOIP_BASE_URL` to use a mirror (which must also serve `SHA256SUMS.txt`).
