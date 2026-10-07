#!/usr/bin/env python3
"""生成倒计时两侧的地图 SVG 片段（江西省 / 同奈省）。

数据来源：
  江西省：DataV 全国省市区边界 360000_full.json
  同奈省：geoBoundaries VNM ADM1 / ADM2（简化版）

输出：tools/out/jiangxi.svg、tools/out/dongnai.svg（直接内联进 index.html）
"""
import json
import math
import os
import sys
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "out")
CACHE = os.path.join(BASE, ".map-cache")

URL_JX = "https://geo.datav.aliyun.com/areas_v3/bound/360000_full.json"
URL_VN1 = ("https://github.com/wmgeolab/geoBoundaries/raw/9469f09/"
           "releaseData/gbOpen/VNM/ADM1/geoBoundaries-VNM-ADM1_simplified.geojson")
URL_VN2 = ("https://github.com/wmgeolab/geoBoundaries/raw/9469f09/"
           "releaseData/gbOpen/VNM/ADM2/geoBoundaries-VNM-ADM2_simplified.geojson")

TARGET_W = 300.0          # viewBox 宽度（1 单位 ≈ 1 展示像素）
PAD = 18.0                # 边距，给标注留位
RDP_TOL_JX = 0.020        # 江西容差（度）
RDP_TOL_VN = 0.008        # 同奈容差（度）


def fetch(url, name):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if os.path.exists(path) and os.path.getsize(path) > 1000:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    print("下载", url)
    with urllib.request.urlopen(url, timeout=90) as r:
        raw = r.read().decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        f.write(raw)
    return json.loads(raw)


def rings(geom):
    """几何体 -> [ring, ...]，ring 为 [(lon, lat), ...]"""
    t = geom["type"]
    c = geom["coordinates"]
    out = []
    if t == "Polygon":
        out.extend(c)
    elif t == "MultiPolygon":
        for poly in c:
            out.extend(poly)
    return out


def rdp(points, tol):
    if len(points) < 3:
        return points
    x1, y1 = points[0]
    x2, y2 = points[-1]
    dmax, idx = 0.0, 0
    dx, dy = x2 - x1, y2 - y1
    nrm = math.hypot(dx, dy) or 1e-12
    for i in range(1, len(points) - 1):
        x, y = points[i]
        d = abs(dy * x - dx * y + x2 * y1 - y2 * x1) / nrm
        if d > dmax:
            dmax, idx = d, i
    if dmax > tol:
        left = rdp(points[:idx + 1], tol)
        right = rdp(points[idx:], tol)
        return left[:-1] + right
    return [points[0], points[-1]]


def simplify_ring(ring, tol, min_pts=8):
    pts = ring[:-1] if ring[0] == ring[-1] else ring[:]
    if len(pts) < min_pts:
        return pts
    return rdp(pts, tol)


class Projection:
    def __init__(self, bbox):
        lon0, lat0, lon1, lat1 = bbox
        k = math.cos(math.radians((lat0 + lat1) / 2))
        self.k = k
        self.lon0, self.lat1 = lon0, lat1

    def __call__(self, lon, lat):
        return ((lon - self.lon0) * self.k, (self.lat1 - lat))


def geo_bbox(features):
    lon0 = lat0 = 1e9
    lon1 = lat1 = -1e9
    for f in features:
        for ring in rings(f["geometry"]):
            for lon, lat in ring:
                lon0 = min(lon0, lon)
                lon1 = max(lon1, lon)
                lat0 = min(lat0, lat)
                lat1 = max(lat1, lat)
    return lon0, lat0, lon1, lat1


def path_data(features, proj, tol, scale, off_x, off_y):
    parts = []
    for f in features:
        for ring in rings(f["geometry"]):
            pts = simplify_ring(ring, tol)
            if len(pts) < 3:
                continue
            d = []
            for i, (lon, lat) in enumerate(pts):
                x, y = proj(lon, lat)
                x = x * scale + off_x
                y = y * scale + off_y
                d.append(("M" if i == 0 else "L") +
                         f"{x:.1f} {y:.1f}")
            parts.append("".join(d) + "Z")
    return "".join(parts)


def fit(bbox, target_w, pad):
    """返回 proj, scale, off_x, off_y, view_w, view_h"""
    lon0, lat0, lon1, lat1 = bbox
    proj = Projection(bbox)
    w = (lon1 - lon0) * math.cos(math.radians((lat0 + lat1) / 2))
    h = lat1 - lat0
    inner_w = target_w - 2 * pad
    scale = inner_w / w
    view_h = h * scale + 2 * pad
    return proj, scale, pad, pad, target_w, view_h


def pt(proj, scale, ox, oy, lon, lat):
    x, y = proj(lon, lat)
    return x * scale + ox, y * scale + oy


def centroid(features, target_name, prop="shapeName"):
    """取同名要素最大外环的面积加权质心"""
    best = None
    best_area = -1
    for f in features:
        if f["properties"].get(prop) != target_name:
            continue
        for ring in rings(f["geometry"]):
            pts = ring
            a = 0.0
            cx = cy = 0.0
            for i in range(len(pts) - 1):
                x0, y0 = pts[i]
                x1, y1 = pts[i + 1]
                cross = x0 * y1 - x1 * y0
                a += cross
                cx += (x0 + x1) * cross
                cy += (y0 + y1) * cross
            a /= 2
            if abs(a) < 1e-12:
                continue
            if abs(a) > best_area:
                best_area = abs(a)
                best = (cx / (6 * a), cy / (6 * a))
    return best


def write(name, body):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    print(f"{name}: {len(body)} 字符 -> {path}")


def gen_jiangxi():
    data = fetch(URL_JX, "jx_full.json")
    feats = sorted(data["features"], key=lambda f: f["properties"]["adcode"])
    hl = [f for f in feats if f["properties"]["adcode"] == 360100]
    rest = [f for f in feats if f["properties"]["adcode"] != 360100]
    proj, scale, ox, oy, vw, vh = fit(geo_bbox(feats), TARGET_W, PAD)
    d_rest = path_data(rest, proj, RDP_TOL_JX, scale, ox, oy)
    d_hl = path_data(hl, proj, RDP_TOL_JX, scale, ox, oy)
    lon, lat = hl[0]["properties"]["center"]
    mx, my = pt(proj, scale, ox, oy, lon, lat)
    # 标注避让：南昌在中北部，标签放右侧
    label_x, label_y = mx + 12, my + 5
    anchor = "start"
    if label_x + 52 > vw - 4:
        label_x, anchor = mx - 12, "end"
    svg = (
        f'<svg class="map-svg" viewBox="0 0 {vw:.0f} {vh:.0f}" '
        'preserveAspectRatio="xMidYMid meet" role="img" '
        'data-i18n-aria="aria_map_jx" aria-label="江西省地图，标出南昌市">\n'
        f'          <path class="map-land" d="{d_rest}"/>\n'
        f'          <path class="map-land map-land--hl" d="{d_hl}"/>\n'
        f'          <g class="map-pin" transform="translate({mx:.1f} {my:.1f})">'
        '<circle class="map-pin-halo" r="9"/><circle class="map-pin-dot" r="3.4"/></g>\n'
        f'          <text class="map-label" x="{label_x:.1f}" y="{label_y:.1f}" '
        f'text-anchor="{anchor}" data-i18n="map_nc">南昌市</text>\n'
        '        </svg>\n'
    )
    write("jiangxi.svg", svg)
    print("  viewBox", vw, vh, "pin", round(mx, 1), round(my, 1),
          "len", len(d_rest) + len(d_hl))


def gen_dongnai():
    a1 = fetch(URL_VN1, "vn_adm1.geojson")
    a2 = fetch(URL_VN2, "vn_adm2.geojson")
    prov = [f for f in a1["features"] if f["properties"]["shapeName"] == "Dong Nai"
            or f["properties"]["shapeName"] == "Đồng Nai"]
    if not prov:
        sys.exit("找不到同奈省 ADM1")
    pgeom = prov[0]["geometry"]

    def inside(lon, lat):
        # 射线法判断点是否在省内（用外环近似即可）
        for ring in rings(pgeom):
            xs = [p[0] for p in ring]
            ys = [p[1] for p in ring]
            if not (min(xs) <= lon <= max(xs) and min(ys) <= lat <= max(ys)):
                continue
            cnt = 0
            n = len(ring)
            for i in range(n - 1):
                x1, y1 = ring[i]
                x2, y2 = ring[i + 1]
                if (y1 > lat) != (y2 > lat):
                    xin = x1 + (lat - y1) * (x2 - x1) / (y2 - y1)
                    if xin > lon:
                        cnt += 1
            if cnt % 2:
                return True
        return False

    dists = []
    for f in a2["features"]:
        rs = rings(f["geometry"])
        if not rs:
            continue
        # 用质心判断归属
        pts = rs[0]
        cx = sum(p[0] for p in pts[:-1]) / (len(pts) - 1)
        cy = sum(p[1] for p in pts[:-1]) / (len(pts) - 1)
        if inside(cx, cy):
            dists.append(f)
    names = sorted(f["properties"]["shapeName"] for f in dists)
    print("  同奈县级单位:", names)
    hl = [f for f in dists if f["properties"]["shapeName"] == "Bien Hoa"]
    rest = [f for f in dists if f["properties"]["shapeName"] != "Bien Hoa"]
    if not hl:
        sys.exit("找不到边和市")
    feats = [prov[0]] + dists
    proj, scale, ox, oy, vw, vh = fit(geo_bbox(feats), TARGET_W, PAD)
    d_prov = path_data([prov[0]], proj, RDP_TOL_VN, scale, ox, oy)
    d_rest = path_data(rest, proj, RDP_TOL_VN, scale, ox, oy)
    d_hl = path_data(hl, proj, RDP_TOL_VN, scale, ox, oy)
    c = centroid(dists, "Bien Hoa")
    if not c:
        sys.exit("边和市质心计算失败")
    mx, my = pt(proj, scale, ox, oy, *c)
    label_x, label_y = mx + 12, my + 5
    anchor = "start"
    if label_x + 52 > vw - 4:
        label_x, anchor = mx - 12, "end"
    svg = (
        f'<svg class="map-svg" viewBox="0 0 {vw:.0f} {vh:.0f}" '
        'preserveAspectRatio="xMidYMid meet" role="img" '
        'data-i18n-aria="aria_map_dn" aria-label="同奈省地图，标出边和市">\n'
        f'          <path class="map-land" d="{d_prov}"/>\n'
        f'          <path class="map-line" d="{d_rest}"/>\n'
        f'          <path class="map-land map-land--hl" d="{d_hl}"/>\n'
        f'          <g class="map-pin" transform="translate({mx:.1f} {my:.1f})">'
        '<circle class="map-pin-halo" r="9"/><circle class="map-pin-dot" r="3.4"/></g>\n'
        f'          <text class="map-label" x="{label_x:.1f}" y="{label_y:.1f}" '
        f'text-anchor="{anchor}" data-i18n="map_bh">边和市</text>\n'
        '        </svg>\n'
    )
    write("dongnai.svg", svg)
    print("  viewBox", vw, vh, "pin", round(mx, 1), round(my, 1),
          "len", len(d_prov) + len(d_rest) + len(d_hl))


if __name__ == "__main__":
    gen_jiangxi()
    gen_dongnai()
