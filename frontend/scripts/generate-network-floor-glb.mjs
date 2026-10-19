import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const output = resolve(dirname(fileURLToPath(import.meta.url)), '../public/assets/network-map/open-office-floor.glb')

const hex = value => [((value >> 16) & 255) / 255, ((value >> 8) & 255) / 255, (value & 255) / 255]
const materials = []
const buckets = []
const material = (name, color, roughness, metallic = 0, extras = {}, emissive = 0) => {
  const entry = {
    name,
    pbrMetallicRoughness: { baseColorFactor: [...hex(color), extras.opacity ?? 1], metallicFactor: metallic, roughnessFactor: roughness },
    extras,
  }
  if (emissive) entry.emissiveFactor = hex(emissive)
  if ((extras.opacity ?? 1) < 1) {
    entry.alphaMode = 'BLEND'
    entry.doubleSided = true
  }
  materials.push(entry)
  buckets.push({ positions: [], normals: [], indices: [] })
  return materials.length - 1
}

const MAT = {
  slab: material('Pale stone slab', 0x9eabb4, 0.62, 0.03),
  tile: material('Porcelain floor', 0xbcc4c9, 0.7, 0.01),
  grout: material('Tile joints', 0x73818a, 0.8),
  glass: material('Blue curtain glass', 0x376f93, 0.12, 0.08, { sec360Material: 'glass', opacity: 0.38 }),
  white: material('White structure', 0xe7edef, 0.34, 0.08),
  graphite: material('Graphite core', 0x313d49, 0.52, 0.18),
  charcoal: material('Furniture charcoal', 0x131c24, 0.58, 0.22),
  wood: material('Warm oak', 0xb18354, 0.58, 0.02),
  screen: material('Blue monitor glass', 0x0b315d, 0.18, 0.16, { emissiveIntensity: 2.2 }, 0x0877ff),
  warm: material('Warm column light', 0xffddb0, 0.24, 0.02, { emissiveIntensity: 1.8 }, 0xff9d36),
  green: material('Plant leaves', 0x2f7d4f, 0.82),
  pot: material('Plant pots', 0x26323a, 0.68, 0.12),
  porcelain: material('Porcelain fixtures', 0xd9e4e6, 0.3, 0.02),
}

const rotate = (x, z, angle) => [x * Math.cos(angle) - z * Math.sin(angle), x * Math.sin(angle) + z * Math.cos(angle)]
const addQuad = (bucket, points, normal) => {
  const start = bucket.positions.length / 3
  for (const point of points) bucket.positions.push(...point)
  for (let index = 0; index < 4; index += 1) bucket.normals.push(...normal)
  bucket.indices.push(start, start + 1, start + 2, start, start + 2, start + 3)
}
const addBox = (x, y, z, width, height, depth, mat, rotation = 0) => {
  const bucket = buckets[mat]
  const hx = width / 2
  const hy = height / 2
  const hz = depth / 2
  const point = (px, py, pz) => {
    const [rx, rz] = rotate(px, pz, rotation)
    return [x + rx, y + py, z + rz]
  }
  const normal = (nx, ny, nz) => {
    const [rx, rz] = rotate(nx, nz, rotation)
    return [rx, ny, rz]
  }
  addQuad(bucket, [point(-hx, -hy, hz), point(hx, -hy, hz), point(hx, hy, hz), point(-hx, hy, hz)], normal(0, 0, 1))
  addQuad(bucket, [point(hx, -hy, -hz), point(-hx, -hy, -hz), point(-hx, hy, -hz), point(hx, hy, -hz)], normal(0, 0, -1))
  addQuad(bucket, [point(hx, -hy, hz), point(hx, -hy, -hz), point(hx, hy, -hz), point(hx, hy, hz)], normal(1, 0, 0))
  addQuad(bucket, [point(-hx, -hy, -hz), point(-hx, -hy, hz), point(-hx, hy, hz), point(-hx, hy, -hz)], normal(-1, 0, 0))
  addQuad(bucket, [point(-hx, hy, hz), point(hx, hy, hz), point(hx, hy, -hz), point(-hx, hy, -hz)], normal(0, 1, 0))
  addQuad(bucket, [point(-hx, -hy, -hz), point(hx, -hy, -hz), point(hx, -hy, hz), point(-hx, -hy, hz)], normal(0, -1, 0))
}
const addCylinder = (x, y, z, radiusBottom, radiusTop, height, mat, segments = 14) => {
  const bucket = buckets[mat]
  const start = bucket.positions.length / 3
  for (let index = 0; index <= segments; index += 1) {
    const angle = index / segments * Math.PI * 2
    const nx = Math.cos(angle)
    const nz = Math.sin(angle)
    bucket.positions.push(x + nx * radiusBottom, y - height / 2, z + nz * radiusBottom, x + nx * radiusTop, y + height / 2, z + nz * radiusTop)
    bucket.normals.push(nx, 0, nz, nx, 0, nz)
  }
  for (let index = 0; index < segments; index += 1) {
    const lower = start + index * 2
    bucket.indices.push(lower, lower + 2, lower + 3, lower, lower + 3, lower + 1)
  }
  const addCap = (capY, radius, ny) => {
    const center = bucket.positions.length / 3
    bucket.positions.push(x, capY, z)
    bucket.normals.push(0, ny, 0)
    for (let index = 0; index <= segments; index += 1) {
      const angle = index / segments * Math.PI * 2
      bucket.positions.push(x + Math.cos(angle) * radius, capY, z + Math.sin(angle) * radius)
      bucket.normals.push(0, ny, 0)
      if (index < segments) {
        if (ny > 0) bucket.indices.push(center, center + index + 1, center + index + 2)
        else bucket.indices.push(center, center + index + 2, center + index + 1)
      }
    }
  }
  addCap(y + height / 2, radiusTop, 1)
  addCap(y - height / 2, radiusBottom, -1)
}
const world = (originX, originZ, localX, localZ, rotation) => {
  const [x, z] = rotate(localX, localZ, rotation)
  return [originX + x, originZ + z]
}
const addChair = (x, z, rotation = 0) => {
  addBox(x, 0.34, z, 0.38, 0.12, 0.4, MAT.charcoal, rotation)
  const [backX, backZ] = world(x, z, 0, 0.19, rotation)
  addBox(backX, 0.58, backZ, 0.38, 0.48, 0.09, MAT.charcoal, rotation)
  addCylinder(x, 0.16, z, 0.035, 0.035, 0.3, MAT.charcoal, 8)
}
const addMonitor = (x, z, rotation = 0) => {
  addCylinder(x, 0.67, z, 0.035, 0.035, 0.25, MAT.charcoal, 8)
  addBox(x, 0.82, z, 0.52, 0.34, 0.055, MAT.charcoal, rotation)
  const [screenX, screenZ] = world(x, z, 0, -0.031, rotation)
  addBox(screenX, 0.82, screenZ, 0.44, 0.26, 0.012, MAT.screen, rotation)
}
const addDesk = (x, z, rotation = 0, double = true) => {
  const width = double ? 1.65 : 0.88
  addBox(x, 0.56, z, width, 0.1, 0.7, MAT.white, rotation)
  for (const localX of [-width / 2 + 0.13, width / 2 - 0.13]) {
    const [legX, legZ] = world(x, z, localX, 0, rotation)
    addBox(legX, 0.3, legZ, 0.08, 0.52, 0.54, MAT.graphite, rotation)
  }
  const monitorXs = double ? [-0.42, 0.42] : [0]
  for (const localX of monitorXs) {
    const [monitorX, monitorZ] = world(x, z, localX, 0.05, rotation)
    addMonitor(monitorX, monitorZ, rotation)
    const [chairX, chairZ] = world(x, z, localX, 0.62, rotation)
    addChair(chairX, chairZ, rotation + Math.PI)
  }
}
const addPlant = (x, z, scale = 1) => {
  addCylinder(x, 0.18 * scale, z, 0.22 * scale, 0.18 * scale, 0.36 * scale, MAT.pot, 12)
  addCylinder(x, 0.55 * scale, z, 0.04 * scale, 0.03 * scale, 0.55 * scale, MAT.green, 8)
  for (let index = 0; index < 6; index += 1) {
    const angle = index / 6 * Math.PI * 2
    addCylinder(x + Math.cos(angle) * 0.16 * scale, 0.82 * scale, z + Math.sin(angle) * 0.16 * scale, 0.18 * scale, 0, 0.58 * scale, MAT.green, 8)
  }
}

// Architectural shell.
addBox(0, -0.22, 0, 22.7, 0.44, 12.7, MAT.slab)
addBox(0, 0.025, 0, 22.22, 0.05, 12.18, MAT.tile)
for (let x = -10.5; x <= 10.5; x += 1.05) addBox(x, 0.057, 0, 0.018, 0.012, 12.1, MAT.grout)
for (let z = -5.5; z <= 5.5; z += 1.0) addBox(0, 0.057, z, 22.1, 0.012, 0.018, MAT.grout)
addBox(-11.08, 0.67, 0, 0.08, 1.32, 12.18, MAT.glass)
addBox(11.08, 0.67, 0, 0.08, 1.32, 12.18, MAT.glass)
addBox(0, 0.67, -6.05, 22.2, 1.32, 0.08, MAT.glass)
addBox(0, 0.67, 6.05, 22.2, 1.32, 0.08, MAT.glass)
for (const x of [-11.08, -9, -6.75, -4.5, -2.25, 0, 2.25, 4.5, 6.75, 9, 11.08]) {
  addBox(x, 0.73, -6.05, 0.09, 1.46, 0.12, MAT.white)
  addBox(x, 0.73, 6.05, 0.09, 1.46, 0.12, MAT.white)
}
for (const z of [-4.5, -3, -1.5, 0, 1.5, 3, 4.5]) {
  addBox(-11.08, 0.73, z, 0.12, 1.46, 0.09, MAT.white)
  addBox(11.08, 0.73, z, 0.12, 1.46, 0.09, MAT.white)
}

// Central service core with visible restroom partitions.
addBox(1.35, 0.08, 0, 5.3, 0.09, 3.5, MAT.graphite)
addBox(1.35, 0.72, -1.72, 5.3, 1.35, 0.16, MAT.graphite)
addBox(1.35, 0.72, 1.72, 5.3, 1.35, 0.16, MAT.graphite)
addBox(-1.3, 0.72, 0, 0.16, 1.35, 3.6, MAT.graphite)
addBox(4, 0.72, 0, 0.16, 1.35, 3.6, MAT.graphite)
for (const x of [-0.18, 1.08, 2.34]) addBox(x, 0.62, 0, 0.11, 1.1, 2.85, MAT.graphite)
for (const [x, z] of [[-0.72, -0.95], [0.52, -0.95], [1.77, -0.95], [3.22, -0.95], [-0.72, 0.95], [0.52, 0.95], [1.77, 0.95], [3.22, 0.95]]) {
  addCylinder(x, 0.27, z, 0.18, 0.16, 0.28, MAT.porcelain, 12)
}

// Illuminated structural columns.
for (const [x, z] of [[-9.3, -4.8], [-7.2, 4.8], [-3.25, -3], [4.8, -4.75], [5.2, 4.7], [9.3, -2.5], [9.45, 4.65]]) {
  addBox(x, 0.82, z, 0.46, 1.62, 0.46, MAT.white)
  addBox(x, 0.87, z + 0.237, 0.13, 0.82, 0.025, MAT.warm)
}

// Sparse open-office furniture.
for (const [x, z, rotation, double] of [[-7.8, -3.5, 0, false], [-6.1, 0.9, 0, true], [-4.5, 4.1, 0, true], [6.2, -3.5, 0, true], [7.7, 0.55, Math.PI / 2, false], [7.1, 3.9, 0, true], [9.15, 3.1, Math.PI / 2, false]]) addDesk(x, z, rotation, double)
addBox(-1.9, 0.58, -4.68, 2.65, 0.12, 0.86, MAT.wood)
addBox(-1.9, 0.31, -4.68, 1.8, 0.48, 0.12, MAT.graphite)
for (const x of [-2.75, -2.15, -1.55, -0.95]) {
  addChair(x, -5.3, 0)
  addChair(x, -4.06, Math.PI)
}
// Kitchenette.
addBox(7.95, 0.46, -4.92, 3.0, 0.82, 0.56, MAT.white)
addBox(7.95, 0.9, -4.92, 3.05, 0.08, 0.6, MAT.wood)
addBox(7.65, 0.59, -3.95, 1.65, 0.11, 0.7, MAT.wood)
for (const x of [7.1, 7.65, 8.2]) addChair(x, -3.45, Math.PI)
for (const [x, z, scale] of [[-10, -4.9, 1.15], [-9.8, 4.9, 1.05], [-4.2, -4.85, 0.9], [4.7, -4.85, 1.1], [5.1, 4.82, 0.95], [9.8, -4.6, 1.1], [9.75, 4.85, 1.05]]) addPlant(x, z, scale)

const bufferParts = []
const bufferViews = []
const accessors = []
const meshes = []
let byteOffset = 0
const append = (typed, target) => {
  const bytes = Buffer.from(typed.buffer, typed.byteOffset, typed.byteLength)
  const padding = (4 - bytes.length % 4) % 4
  bufferParts.push(bytes, Buffer.alloc(padding))
  const view = { buffer: 0, byteOffset, byteLength: bytes.length, target }
  bufferViews.push(view)
  byteOffset += bytes.length + padding
  return bufferViews.length - 1
}
const bounds = positions => {
  const min = [Infinity, Infinity, Infinity]
  const max = [-Infinity, -Infinity, -Infinity]
  for (let index = 0; index < positions.length; index += 3) {
    for (let axis = 0; axis < 3; axis += 1) {
      min[axis] = Math.min(min[axis], positions[index + axis])
      max[axis] = Math.max(max[axis], positions[index + axis])
    }
  }
  return { min, max }
}
buckets.forEach((bucket, mat) => {
  if (!bucket.indices.length) return
  const positions = new Float32Array(bucket.positions)
  const normals = new Float32Array(bucket.normals)
  const indices = new Uint32Array(bucket.indices)
  const positionView = append(positions, 34962)
  const normalView = append(normals, 34962)
  const indexView = append(indices, 34963)
  const box = bounds(bucket.positions)
  accessors.push({ bufferView: positionView, componentType: 5126, count: positions.length / 3, type: 'VEC3', min: box.min, max: box.max })
  const positionAccessor = accessors.length - 1
  accessors.push({ bufferView: normalView, componentType: 5126, count: normals.length / 3, type: 'VEC3' })
  const normalAccessor = accessors.length - 1
  accessors.push({ bufferView: indexView, componentType: 5125, count: indices.length, type: 'SCALAR' })
  const indexAccessor = accessors.length - 1
  meshes.push({ name: materials[mat].name, primitives: [{ attributes: { POSITION: positionAccessor, NORMAL: normalAccessor }, indices: indexAccessor, material: mat }] })
})

const binary = Buffer.concat(bufferParts)
const gltf = {
  asset: { version: '2.0', generator: 'SEC360 Network Floor Generator' },
  scene: 0,
  scenes: [{ nodes: meshes.map((_, index) => index) }],
  nodes: meshes.map((_, index) => ({ mesh: index })),
  meshes,
  materials,
  accessors,
  bufferViews,
  buffers: [{ byteLength: binary.length }],
}
const json = Buffer.from(JSON.stringify(gltf))
const jsonPadding = (4 - json.length % 4) % 4
const paddedJson = Buffer.concat([json, Buffer.alloc(jsonPadding, 0x20)])
const binaryPadding = (4 - binary.length % 4) % 4
const paddedBinary = Buffer.concat([binary, Buffer.alloc(binaryPadding)])
const header = Buffer.alloc(12)
header.writeUInt32LE(0x46546c67, 0)
header.writeUInt32LE(2, 4)
header.writeUInt32LE(12 + 8 + paddedJson.length + 8 + paddedBinary.length, 8)
const jsonHeader = Buffer.alloc(8)
jsonHeader.writeUInt32LE(paddedJson.length, 0)
jsonHeader.writeUInt32LE(0x4e4f534a, 4)
const binaryHeader = Buffer.alloc(8)
binaryHeader.writeUInt32LE(paddedBinary.length, 0)
binaryHeader.writeUInt32LE(0x004e4942, 4)

mkdirSync(dirname(output), { recursive: true })
writeFileSync(output, Buffer.concat([header, jsonHeader, paddedJson, binaryHeader, paddedBinary]))
console.log(`Wrote ${output} (${binary.length.toLocaleString()} binary bytes, ${meshes.length} material meshes)`)
