import cadquery as cq
from pathlib import Path

OUT = Path(__file__).resolve().parent
W = H = 32.0
T = 14.0
CORNER = 7.0
FRONT_EDGE = 2.4
HOLE = 19.1
POCKET = 23.0
FRONT_WALL = 2.0
CHANNEL_DIAMETER = 3.0
CHANNEL_LOWER = 0.8

s = cq.Workplane("XY").box(W, H, T, centered=(True, True, False)).edges("|Z").fillet(CORNER)
s = s.faces("<Z").edges().fillet(FRONT_EDGE)
s = s.cut(cq.Workplane("XY").circle(HOLE / 2).extrude(T + 1))
s = s.cut(
    cq.Workplane("XY")
    .workplane(offset=FRONT_WALL)
    .circle(POCKET / 2)
    .extrude(T - FRONT_WALL + 1)
)

# Цилиндр формирует полукруглый канал на задней поверхности корпуса.
channel = cq.Solid.makeCylinder(
    CHANNEL_DIAMETER / 2,
    H / 2 + 2,
    cq.Vector(0, 1, T - CHANNEL_LOWER),
    cq.Vector(0, -1, 0),
)
s = s.cut(channel)

solid = s.val()
assert solid.isValid() and len(solid.Solids()) == 1

name = "R558S_case_v3_deeper_round_channel"
cq.exporters.export(s, str(OUT / (name + ".stl")), tolerance=0.025, angularTolerance=0.1)
cq.exporters.export(s, str(OUT / (name + ".step")))
print("ok", solid.Volume(), solid.BoundingBox().xlen, solid.BoundingBox().ylen, solid.BoundingBox().zlen)
