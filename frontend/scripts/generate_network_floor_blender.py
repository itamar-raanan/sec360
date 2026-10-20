"""Build SEC360's premium open-office floor as a Blender-authored GLB.

Run with Blender's Python module installed (bpy 5.2+):
    python scripts/generate_network_floor_blender.py

The script also renders a review image before exporting the web asset.  Geometry
transforms are baked because SEC360's lightweight runtime GLB reader intentionally
loads only mesh primitives and materials.
"""

from __future__ import annotations

import math
from pathlib import Path

import bpy
from mathutils import Vector


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "public/assets/network-map/open-office-floor.glb"
SOURCE_DIR = ROOT / "assets/network-map"
PREVIEW = SOURCE_DIR / "open-office-floor-preview.png"
BLEND_SOURCE = SOURCE_DIR / "open-office-floor.blend"


def reset_scene() -> None:
    bpy.ops.wm.read_factory_settings(use_empty=True)
    scene = bpy.context.scene
    scene.render.engine = "BLENDER_EEVEE"
    scene.render.resolution_x = 1440
    scene.render.resolution_y = 900
    scene.render.resolution_percentage = 100
    scene.render.image_settings.file_format = "PNG"
    scene.render.film_transparent = True
    scene.render.image_settings.color_mode = "RGBA"
    scene.render.resolution_percentage = 100
    scene.view_settings.look = "AgX - Medium High Contrast"
    bpy.context.preferences.filepaths.save_version = 0
    scene.world = bpy.data.worlds.new("SEC360 night environment")
    scene.world.color = (0.004, 0.009, 0.018)


def material(name: str, color: tuple[float, float, float, float], *, roughness=0.45,
             metallic=0.0, emission=None, emission_strength=0.0, transmission=0.0):
    mat = bpy.data.materials.new(name)
    mat.diffuse_color = color
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes.get("Principled BSDF")
    bsdf.inputs["Base Color"].default_value = color
    bsdf.inputs["Roughness"].default_value = roughness
    bsdf.inputs["Metallic"].default_value = metallic
    if emission:
        bsdf.inputs["Emission Color"].default_value = (*emission, 1)
        bsdf.inputs["Emission Strength"].default_value = emission_strength
    if transmission:
        bsdf.inputs["Transmission Weight"].default_value = transmission
        bsdf.inputs["IOR"].default_value = 1.46
        bsdf.inputs["Coat Weight"].default_value = 0.45
        mat.surface_render_method = "DITHERED"
        mat.diffuse_color = (*color[:3], min(color[3], 0.42))
        mat["sec360Material"] = "glass"
    return mat


MAT = {}


def create_materials() -> None:
    MAT.update({
        "slab": material("Architectural concrete slab", (0.31, 0.38, 0.43, 1), roughness=0.72),
        "floor": material("Silver porcelain floor", (0.43, 0.50, 0.55, 1), roughness=0.5, metallic=0.04),
        "grout": material("Graphite tile joints", (0.12, 0.18, 0.23, 1), roughness=0.8),
        "glass": material("Blue curtain glass", (0.025, 0.24, 0.42, 0.34), roughness=0.08, metallic=0.08, transmission=0.72),
        "frame": material("Pearl aluminium frames", (0.72, 0.79, 0.84, 1), roughness=0.24, metallic=0.72),
        "white": material("Warm architectural white", (0.78, 0.82, 0.83, 1), roughness=0.36),
        "core": material("Graphite service core", (0.075, 0.12, 0.16, 1), roughness=0.38, metallic=0.16),
        "charcoal": material("Charcoal furniture", (0.025, 0.045, 0.065, 1), roughness=0.42, metallic=0.32),
        "fabric": material("Midnight chair fabric", (0.035, 0.085, 0.12, 1), roughness=0.83),
        "oak": material("Natural oak worktops", (0.45, 0.245, 0.105, 1), roughness=0.5),
        "screen": material("Blue monitor glass", (0.008, 0.08, 0.22, 1), roughness=0.13, metallic=0.14,
                           emission=(0.01, 0.27, 1.0), emission_strength=2.8),
        "warm": material("Warm inset illumination", (0.85, 0.47, 0.16, 1), roughness=0.2,
                         emission=(1.0, 0.33, 0.075), emission_strength=5.0),
        "cyan": material("Network cyan illumination", (0.01, 0.42, 0.55, 1), roughness=0.18,
                         emission=(0.0, 0.8, 1.0), emission_strength=6.0),
        "leaf": material("Deep green foliage", (0.018, 0.22, 0.10, 1), roughness=0.75),
        "leaf2": material("Emerald foliage", (0.03, 0.36, 0.16, 1), roughness=0.73),
        "pot": material("Black ceramic planters", (0.025, 0.038, 0.045, 1), roughness=0.32, metallic=0.24),
        "porcelain": material("Porcelain fixtures", (0.72, 0.80, 0.82, 1), roughness=0.24),
    })


def assign(obj, mat):
    obj.data.materials.append(mat)
    return obj


def bevel(obj, amount=0.055, segments=3):
    modifier = obj.modifiers.new("Soft manufactured edges", "BEVEL")
    modifier.width = amount
    modifier.segments = segments
    modifier.limit_method = "ANGLE"
    return obj


def box(name, location, scale, mat, *, bevel_size=0.04, rotation=0.0):
    bpy.ops.mesh.primitive_cube_add(location=location, rotation=(0, 0, rotation))
    obj = bpy.context.object
    obj.name = name
    obj.scale = (scale[0] / 2, scale[1] / 2, scale[2] / 2)
    bpy.ops.object.transform_apply(location=False, rotation=False, scale=True)
    assign(obj, mat)
    if bevel_size:
        bevel(obj, min(bevel_size, min(scale) * 0.42))
    return obj


def cylinder(name, location, radius, depth, mat, *, vertices=24, bevel_size=0.025):
    bpy.ops.mesh.primitive_cylinder_add(vertices=vertices, radius=radius, depth=depth, location=location)
    obj = bpy.context.object
    obj.name = name
    assign(obj, mat)
    if bevel_size:
        bevel(obj, bevel_size, 2)
    return obj


def sphere(name, location, scale, mat):
    bpy.ops.mesh.primitive_ico_sphere_add(subdivisions=2, radius=1, location=location)
    obj = bpy.context.object
    obj.name = name
    obj.scale = scale
    bpy.ops.object.transform_apply(location=False, rotation=False, scale=True)
    assign(obj, mat)
    for polygon in obj.data.polygons:
        polygon.use_smooth = True
    return obj


def local(origin, offset, angle=0.0):
    x, y = offset
    return (origin[0] + x * math.cos(angle) - y * math.sin(angle),
            origin[1] + x * math.sin(angle) + y * math.cos(angle))


def add_area_light(name, location, energy, color, size=4.0):
    data = bpy.data.lights.new(name, "AREA")
    data.energy = energy
    data.color = color
    data.shape = "DISK"
    data.size = size
    obj = bpy.data.objects.new(name, data)
    bpy.context.collection.objects.link(obj)
    obj.location = location
    obj.rotation_euler = (0, 0, 0)
    return obj


def add_chair(x, y, angle=0.0):
    # Five-star base, upholstered seat, curved back and arm rests.
    cylinder("Chair gas lift", (x, y, 0.37), 0.035, 0.38, MAT["charcoal"], vertices=12)
    for arm_angle in (0, 1.256, 2.512, 3.768, 5.024):
        dx, dy = math.cos(arm_angle) * 0.18, math.sin(arm_angle) * 0.18
        box("Chair caster leg", (x + dx / 2, y + dy / 2, 0.18), (0.24, 0.035, 0.035), MAT["charcoal"],
            bevel_size=0.015, rotation=arm_angle)
        cylinder("Chair caster", (x + dx, y + dy, 0.16), 0.035, 0.045, MAT["charcoal"], vertices=12)
    box("Ergonomic seat", (x, y, 0.57), (0.54, 0.5, 0.13), MAT["fabric"], bevel_size=0.09, rotation=angle)
    bx, by = local((x, y), (0, 0.235), angle)
    back = box("Curved chair back", (bx, by, 0.91), (0.56, 0.11, 0.63), MAT["fabric"], bevel_size=0.09, rotation=angle)
    back.rotation_euler.rotate_axis("X", math.radians(-7))
    for side in (-0.28, 0.28):
        ax, ay = local((x, y), (side, 0.03), angle)
        box("Chair arm", (ax, ay, 0.72), (0.055, 0.38, 0.055), MAT["charcoal"], bevel_size=0.02, rotation=angle)


def add_monitor(x, y, angle=0.0):
    cylinder("Monitor stem", (x, y, 0.99), 0.032, 0.33, MAT["charcoal"], vertices=16)
    box("Monitor foot", (x, y, 0.82), (0.37, 0.22, 0.035), MAT["charcoal"], bevel_size=0.02, rotation=angle)
    box("Monitor bezel", (x, y, 1.19), (0.64, 0.075, 0.43), MAT["charcoal"], bevel_size=0.045, rotation=angle)
    sx, sy = local((x, y), (0, -0.042), angle)
    box("Live blue display", (sx, sy, 1.19), (0.56, 0.012, 0.35), MAT["screen"], bevel_size=0.018, rotation=angle)


def add_desk(x, y, angle=0.0, seats=2):
    width = 2.25 if seats == 2 else 1.14
    box("Oak workstation top", (x, y, 0.79), (width, 0.88, 0.09), MAT["oak"], bevel_size=0.07, rotation=angle)
    for dx in (-width / 2 + 0.16, width / 2 - 0.16):
        lx, ly = local((x, y), (dx, 0), angle)
        box("Workstation metal leg", (lx, ly, 0.42), (0.075, 0.66, 0.7), MAT["frame"], bevel_size=0.025, rotation=angle)
    positions = (-0.55, 0.55) if seats == 2 else (0,)
    for dx in positions:
        mx, my = local((x, y), (dx, -0.1), angle)
        add_monitor(mx, my, angle)
        cx, cy = local((x, y), (dx, 0.75), angle)
        add_chair(cx, cy, angle + math.pi)


def add_plant(x, y, scale=1.0):
    cylinder("Ceramic planter", (x, y, 0.28 * scale), 0.26 * scale, 0.5 * scale, MAT["pot"], vertices=24, bevel_size=0.04)
    cylinder("Plant trunk", (x, y, 0.72 * scale), 0.035 * scale, 0.72 * scale, MAT["oak"], vertices=10)
    for idx in range(9):
        angle = idx * math.tau / 9 + (idx % 2) * 0.2
        radius = (0.18 + (idx % 3) * 0.06) * scale
        leaf = sphere("Sculpted foliage", (x + math.cos(angle) * radius, y + math.sin(angle) * radius,
                                          (0.88 + (idx % 4) * 0.1) * scale),
                      (0.12 * scale, 0.38 * scale, 0.09 * scale), MAT["leaf2"] if idx % 2 else MAT["leaf"])
        leaf.rotation_euler = (math.radians(30), math.radians(-15), angle)


def build_shell():
    box("Floating structural slab", (0, 0, -0.27), (23.4, 13.4, 0.54), MAT["slab"], bevel_size=0.16)
    box("Raised porcelain floor", (0, 0, 0.035), (22.86, 12.86, 0.12), MAT["floor"], bevel_size=0.045)
    for x in [i * 1.04 for i in range(-10, 11)]:
        box("Precision floor joint", (x, 0, 0.102), (0.016, 12.72, 0.009), MAT["grout"], bevel_size=0)
    for y in [i * 1.02 for i in range(-5, 6)]:
        box("Precision floor joint", (0, y, 0.102), (22.7, 0.016, 0.009), MAT["grout"], bevel_size=0)

    # Individual glass bays yield readable reflections and architectural rhythm.
    for x in [i * 2.18 for i in range(-5, 6)]:
        for edge_y in (-6.37, 6.37):
            box("Blue curtain glass panel", (x, edge_y, 1.13), (2.05, 0.045, 2.08), MAT["glass"], bevel_size=0.015)
            box("Curtain-wall mullion", (x - 1.06, edge_y, 1.18), (0.075, 0.12, 2.3), MAT["frame"], bevel_size=0.018)
    for y in [i * 2.0 for i in range(-3, 4)]:
        for edge_x in (-11.37, 11.37):
            box("Blue curtain glass panel", (edge_x, y, 1.13), (0.045, 1.88, 2.08), MAT["glass"], bevel_size=0.015)
            box("Curtain-wall mullion", (edge_x, y - 0.96, 1.18), (0.12, 0.075, 2.3), MAT["frame"], bevel_size=0.018)
    for edge_y in (-6.37, 6.37):
        box("Curtain-wall rail", (0, edge_y, 2.25), (22.85, 0.11, 0.1), MAT["frame"], bevel_size=0.025)
    for edge_x in (-11.37, 11.37):
        box("Curtain-wall rail", (edge_x, 0, 2.25), (0.11, 12.75, 0.1), MAT["frame"], bevel_size=0.025)


def build_core():
    # Dark service/restroom block with open top so the floor reads from above.
    box("Service core plinth", (1.05, 0.05, 0.17), (5.7, 3.8, 0.16), MAT["core"], bevel_size=0.05)
    for y in (-1.83, 1.83):
        box("Service core wall", (1.05, y, 1.13), (5.7, 0.18, 2.08), MAT["core"], bevel_size=0.055)
    for x in (-1.72, 3.82):
        box("Service core wall", (x, 0, 1.13), (0.18, 3.7, 2.08), MAT["core"], bevel_size=0.055)
    for x in (-0.45, 0.82, 2.09):
        box("Restroom partition", (x, 0.12, 0.92), (0.12, 2.92, 1.56), MAT["core"], bevel_size=0.035)
    for x in (-1.12, 0.17, 1.44, 3.08):
        for y in (-0.92, 0.94):
            cylinder("Porcelain fixture", (x, y, 0.38), 0.22, 0.4, MAT["porcelain"], vertices=24, bevel_size=0.045)


def build_columns():
    for x, y in [(-9.4, -4.9), (-7.2, 4.85), (-3.25, -3.2), (4.8, -4.85),
                 (5.1, 4.8), (9.2, -2.45), (9.4, 4.72)]:
        box("Illuminated column", (x, y, 1.05), (0.54, 0.54, 2.05), MAT["white"], bevel_size=0.08)
        box("Warm column reveal", (x, y - 0.285, 1.12), (0.17, 0.022, 1.18), MAT["warm"], bevel_size=0.035)


def build_furniture():
    for desk in [(-7.8, -3.35, 0, 1), (-6.5, 0.75, 0, 2), (-4.7, 4.05, 0, 2),
                 (6.4, -3.5, 0, 2), (8.0, 0.4, math.pi / 2, 1), (7.2, 3.8, 0, 2),
                 (9.45, 2.7, math.pi / 2, 1)]:
        add_desk(*desk)

    # Executive glass meeting room furniture without enclosing walls.
    box("Boardroom table", (-2.25, -4.65, 0.8), (3.35, 1.0, 0.12), MAT["oak"], bevel_size=0.14)
    box("Boardroom pedestal", (-2.25, -4.65, 0.45), (1.4, 0.45, 0.64), MAT["core"], bevel_size=0.08)
    for x in (-3.55, -2.68, -1.82, -0.95):
        add_chair(x, -5.42, 0)
        add_chair(x, -3.88, math.pi)

    # Kitchenette, coffee island and detailed bar seating.
    box("Kitchen cabinets", (7.92, -5.02, 0.55), (3.65, 0.62, 0.92), MAT["white"], bevel_size=0.055)
    box("Kitchen counter", (7.92, -5.02, 1.04), (3.8, 0.72, 0.1), MAT["oak"], bevel_size=0.05)
    for x in (6.7, 7.3, 7.9, 8.5, 9.1):
        box("Cabinet reveal", (x, -5.345, 0.56), (0.024, 0.012, 0.68), MAT["core"], bevel_size=0)
    box("Coffee island", (7.72, -3.72, 0.79), (2.15, 0.88, 0.11), MAT["oak"], bevel_size=0.09)
    box("Coffee island base", (7.72, -3.72, 0.45), (1.48, 0.58, 0.65), MAT["core"], bevel_size=0.065)
    for x in (7.05, 7.72, 8.39):
        add_chair(x, -2.95, math.pi)

    for plant in [(-10.25, -4.95, 1.05), (-9.95, 4.92, 1.0), (-4.25, -4.9, 0.82),
                  (4.72, -4.9, 1.0), (5.12, 4.86, 0.88), (9.82, -4.72, 1.0), (9.8, 4.82, 0.96)]:
        add_plant(*plant)


def build_network_fixtures():
    # Three premium access points plus a low network switch; live app overlays sit above these.
    for x, y in [(-5.2, -1.25), (1.35, 3.75), (7.85, 1.95)]:
        cylinder("Wireless access point", (x, y, 0.24), 0.48, 0.18, MAT["white"], vertices=48, bevel_size=0.07)
        cylinder("Access point halo", (x, y, 0.35), 0.23, 0.025, MAT["cyan"], vertices=48, bevel_size=0.01)
    box("Network switch chassis", (-0.7, 4.78, 0.43), (2.4, 0.72, 0.58), MAT["charcoal"], bevel_size=0.08)
    for idx in range(12):
        x = -1.62 + idx * 0.165
        box("Switch port", (x, 4.405, 0.46), (0.105, 0.018, 0.075), MAT["cyan"], bevel_size=0.012)


def setup_camera_and_lighting():
    camera_data = bpy.data.cameras.new("SEC360 isometric review camera")
    camera = bpy.data.objects.new("SEC360 isometric review camera", camera_data)
    bpy.context.collection.objects.link(camera)
    bpy.context.scene.camera = camera
    camera.location = (18.8, -22.5, 20.4)
    camera.data.lens = 56
    camera.data.type = "ORTHO"
    camera.data.ortho_scale = 27.2
    direction = Vector((0.1, 0.05, 0.45)) - camera.location
    camera.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()

    add_area_light("Large cool architectural key", (-7, -7, 18), 1750, (0.42, 0.68, 1.0), 11)
    add_area_light("Warm perimeter fill", (10, 4, 10), 1050, (1.0, 0.48, 0.20), 8)
    add_area_light("Soft frontal fill", (5, -12, 7), 850, (0.45, 0.78, 1.0), 7)
    for x, y in [(-9.4, -4.9), (-3.25, -3.2), (4.8, -4.85), (5.1, 4.8), (9.4, 4.72)]:
        light_data = bpy.data.lights.new("Warm practical light", "POINT")
        light_data.energy = 46
        light_data.color = (1.0, 0.26, 0.055)
        light_data.shadow_soft_size = 1.0
        light = bpy.data.objects.new("Warm practical light", light_data)
        bpy.context.collection.objects.link(light)
        light.location = (x, y, 1.25)


def bake_mesh_transforms():
    bpy.ops.object.select_all(action="DESELECT")
    mesh_objects = [obj for obj in bpy.context.scene.objects if obj.type == "MESH"]
    for obj in mesh_objects:
        obj.select_set(True)
        bpy.context.view_layer.objects.active = obj
        # Apply modifiers first to retain bevels in the exported geometry.
        for modifier in list(obj.modifiers):
            try:
                bpy.ops.object.modifier_apply(modifier=modifier.name)
            except RuntimeError:
                pass
        bpy.ops.object.transform_apply(location=True, rotation=True, scale=True)
        obj.select_set(False)


def consolidate_meshes_by_material():
    """Collapse hundreds of authored parts into one web mesh per material."""
    mesh_objects = [obj for obj in bpy.context.scene.objects if obj.type == "MESH"]
    material_groups = {}
    for obj in mesh_objects:
        mat = obj.data.materials[0] if obj.data.materials else None
        material_groups.setdefault(mat, []).append(obj)
    for mat, objects in material_groups.items():
        bpy.ops.object.select_all(action="DESELECT")
        for obj in objects:
            obj.select_set(True)
        bpy.context.view_layer.objects.active = objects[0]
        bpy.ops.object.join()
        objects[0].name = mat.name if mat else "SEC360 floor geometry"


def render_and_export():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    scene = bpy.context.scene
    scene.render.filepath = str(PREVIEW)
    bpy.ops.render.render(write_still=True)

    # Preserve the fully editable authored scene, then optimize a copy in memory
    # for fast browser loading.
    bpy.ops.wm.save_as_mainfile(filepath=str(BLEND_SOURCE))
    consolidate_meshes_by_material()

    # Web export excludes review camera and lights; SEC360 supplies runtime lighting.
    for obj in scene.objects:
        obj.select_set(obj.type == "MESH")
    bpy.ops.export_scene.gltf(
        filepath=str(OUTPUT),
        export_format="GLB",
        use_selection=True,
        export_apply=True,
        export_extras=True,
        export_cameras=False,
        export_lights=False,
        export_materials="EXPORT",
        export_normals=True,
        export_yup=True,
    )
    print(f"Rendered {PREVIEW}")
    print(f"Exported {OUTPUT}")


def main():
    reset_scene()
    create_materials()
    build_shell()
    build_core()
    build_columns()
    build_furniture()
    build_network_fixtures()
    setup_camera_and_lighting()
    bake_mesh_transforms()
    render_and_export()


if __name__ == "__main__":
    main()
