import { useEffect, useRef, useState } from 'react'

import type { MapAttachment, MapEquipment, MapFloor } from './types'

interface Props {
  floors: MapFloor[]
  equipment: MapEquipment[]
  attachments: MapAttachment[]
  selectedFloorId: string | null
  selectedEquipmentId: string | null
  selectedAttachmentId: string | null
  onSelectFloor: (id: string) => void
  onSelectEquipment: (id: string) => void
  onSelectAttachment: (id: string) => void
}

function webglAvailable() {
  try {
    const canvas = document.createElement('canvas')
    return Boolean(canvas.getContext('webgl2') || canvas.getContext('webgl'))
  } catch {
    return false
  }
}

function seededRandom(seed: number) {
  let value = seed % 2147483647
  return () => {
    value = (value * 16807) % 2147483647
    return (value - 1) / 2147483646
  }
}

export default function NetworkMapScene(props: Props) {
  const hostRef = useRef<HTMLDivElement>(null)
  const propsRef = useRef(props)
  const [failed, setFailed] = useState(!webglAvailable())
  propsRef.current = props

  useEffect(() => {
    const host = hostRef.current
    if (!host || failed) return
    let disposed = false
    let frame = 0
    let observer: ResizeObserver | null = null
    let cleanup = () => undefined

    const start = async () => {
      try {
        const vendorUrl = (parts: string[]) => `${window.location.origin}/${parts.join('/')}`
        const THREE: any = await import(/* @vite-ignore */ vendorUrl(['vendor', 'three', 'three.module.js']))
        const { OrbitControls }: any = await import(/* @vite-ignore */ vendorUrl(['vendor', 'three', 'addons', 'controls', 'OrbitControls.js']))
        if (disposed) return

        const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
        const scene = new THREE.Scene()
        scene.background = null
        scene.fog = new THREE.FogExp2(0x030913, 0.013)

        const camera = new THREE.PerspectiveCamera(33, 1, 0.1, 260)
        const overviewPosition = new THREE.Vector3(31, 22, 50)
        // A high three-quarter view keeps the entire cutaway readable, matching the
        // architectural reference instead of hiding furniture behind perimeter walls.
        const detailPosition = new THREE.Vector3(22, 40, 42)
        const overviewLook = new THREE.Vector3(-2.5, 10.7, 0)
        const detailLook = new THREE.Vector3(3.4, 7.65, -0.35)
        camera.position.copy(overviewPosition)
        camera.lookAt(overviewLook)

        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' })
        renderer.setClearColor(0x000000, 0)
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
        renderer.outputColorSpace = THREE.SRGBColorSpace
        renderer.toneMapping = THREE.ACESFilmicToneMapping
        renderer.toneMappingExposure = 1.06
        renderer.shadowMap.enabled = true
        renderer.shadowMap.type = THREE.PCFSoftShadowMap
        renderer.domElement.style.touchAction = 'none'
        host.appendChild(renderer.domElement)

        const controls = new OrbitControls(camera, renderer.domElement)
        controls.enableDamping = true
        controls.dampingFactor = 0.065
        controls.enableRotate = false
        controls.enablePan = false
        controls.enableZoom = false
        controls.minDistance = 18
        controls.maxDistance = 82
        controls.minPolarAngle = Math.PI * 0.08
        controls.maxPolarAngle = Math.PI * 0.49
        controls.target.copy(overviewLook)

        scene.add(new THREE.HemisphereLight(0xb4e3ff, 0x02050a, 1.65))
        const key = new THREE.DirectionalLight(0xf0f8ff, 2.8)
        key.position.set(22, 36, 18)
        key.castShadow = true
        key.shadow.mapSize.set(2048, 2048)
        key.shadow.camera.near = 1
        key.shadow.camera.far = 90
        key.shadow.camera.left = -35
        key.shadow.camera.right = 35
        key.shadow.camera.top = 35
        key.shadow.camera.bottom = -35
        scene.add(key)
        const cyanLight = new THREE.PointLight(0x14dbe5, 18, 58, 2)
        cyanLight.position.set(-8, 13, 7)
        scene.add(cyanLight)
        const blueLight = new THREE.PointLight(0x2c72ff, 14, 70, 2)
        blueLight.position.set(15, 14, -14)
        scene.add(blueLight)

        const world = new THREE.Group()
        scene.add(world)
        const proceduralEnvironment = new THREE.Group()
        proceduralEnvironment.visible = false
        world.add(proceduralEnvironment)
        let interactive: any[] = []
        let pulses: Array<{ mesh: any; curve: any; phase: number; speed: number }> = []
        let rings: Array<{ mesh: any; phase: number }> = []

        const addBox = (parent: any, size: number[], position: number[], material: any) => {
          const mesh = new THREE.Mesh(new THREE.BoxGeometry(...size), material)
          mesh.position.set(...position)
          mesh.castShadow = true
          mesh.receiveShadow = true
          parent.add(mesh)
          return mesh
        }
        const addEdges = (parent: any, mesh: any, color = 0x5ea3c7, opacity = 0.42) => {
          const edges = new THREE.LineSegments(new THREE.EdgesGeometry(mesh.geometry), new THREE.LineBasicMaterial({ color, transparent: true, opacity }))
          edges.position.copy(mesh.position)
          parent.add(edges)
        }
        const setGroupOpacity = (group: any, opacity: number) => {
          group.traverse((object: any) => {
            if (!object.material) return
            const materials = Array.isArray(object.material) ? object.material : [object.material]
            materials.forEach((material: any) => {
              if (material.userData.baseOpacity === undefined) material.userData.baseOpacity = material.opacity ?? 1
              material.transparent = true
              material.opacity = material.userData.baseOpacity * opacity
            })
          })
        }
        const disposeGroup = (group: any) => {
          group.traverse((object: any) => {
            object.geometry?.dispose?.()
            const materials = Array.isArray(object.material) ? object.material : object.material ? [object.material] : []
            materials.forEach((material: any) => { material.map?.dispose?.(); material.dispose?.() })
          })
          group.parent?.remove(group)
        }
        const makeLabel = (text: string, accent = false) => {
          const canvas = document.createElement('canvas')
          const context = canvas.getContext('2d')!
          canvas.width = 512
          canvas.height = 124
          context.scale(2, 2)
          context.font = '600 17px ui-sans-serif, system-ui, sans-serif'
          context.textAlign = 'center'
          context.textBaseline = 'middle'
          context.fillStyle = 'rgba(4, 12, 22, .92)'
          context.strokeStyle = accent ? 'rgba(34, 211, 238, .82)' : 'rgba(120, 166, 190, .42)'
          context.lineWidth = 1
          context.beginPath()
          context.roundRect(4, 4, 248, 54, 10)
          context.fill()
          context.stroke()
          context.fillStyle = accent ? '#d9fbff' : '#c6d5df'
          context.fillText(text.slice(0, 24), 128, 31)
          const texture = new THREE.CanvasTexture(canvas)
          texture.colorSpace = THREE.SRGBColorSpace
          const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: false }))
          sprite.scale.set(3.15, 0.78, 1)
          sprite.renderOrder = 20
          return sprite
        }

        const loadGlbAsset = async (url: string) => {
          const response = await fetch(url)
          if (!response.ok) throw new Error(`Floor asset request failed with ${response.status}`)
          const file = await response.arrayBuffer()
          const view = new DataView(file)
          if (view.getUint32(0, true) !== 0x46546c67 || view.getUint32(4, true) !== 2) throw new Error('Floor asset is not a glTF 2.0 binary')
          let offset = 12
          let document: any = null
          let binary: ArrayBuffer | null = null
          while (offset < file.byteLength) {
            const length = view.getUint32(offset, true)
            const type = view.getUint32(offset + 4, true)
            const start = offset + 8
            if (type === 0x4e4f534a) document = JSON.parse(new TextDecoder().decode(new Uint8Array(file, start, length)).trim())
            if (type === 0x004e4942) binary = file.slice(start, start + length)
            offset = start + length
          }
          if (!document || !binary) throw new Error('Floor asset is missing its JSON or binary chunk')
          const componentCount: Record<string, number> = { SCALAR: 1, VEC2: 2, VEC3: 3, VEC4: 4 }
          const readAccessor = (index: number) => {
            const accessor = document.accessors[index]
            const bufferView = document.bufferViews[accessor.bufferView]
            const length = accessor.count * componentCount[accessor.type]
            const byteOffset = (bufferView.byteOffset || 0) + (accessor.byteOffset || 0)
            if (accessor.componentType === 5126) return new Float32Array(binary!, byteOffset, length)
            if (accessor.componentType === 5125) return new Uint32Array(binary!, byteOffset, length)
            if (accessor.componentType === 5123) return new Uint16Array(binary!, byteOffset, length)
            throw new Error(`Unsupported floor asset component type ${accessor.componentType}`)
          }
          const loadedMaterials = document.materials.map((entry: any) => {
            const pbr = entry.pbrMetallicRoughness || {}
            const factor = pbr.baseColorFactor || [1, 1, 1, 1]
            const common = {
              color: new THREE.Color().setRGB(factor[0], factor[1], factor[2]),
              roughness: pbr.roughnessFactor ?? 1,
              metalness: pbr.metallicFactor ?? 0,
              transparent: factor[3] < 1,
              opacity: factor[3],
            }
            const loaded = entry.extras?.sec360Material === 'glass' || /glass/i.test(entry.name || '')
              ? new THREE.MeshPhysicalMaterial({ ...common, transmission: 0.34, thickness: 0.08, clearcoat: 0.76, side: THREE.DoubleSide, depthWrite: false })
              : new THREE.MeshStandardMaterial(common)
            loaded.name = entry.name || ''
            if (entry.emissiveFactor) {
              loaded.emissive.setRGB(...entry.emissiveFactor)
              loaded.emissiveIntensity = entry.extras?.emissiveIntensity ?? 1
            }
            return loaded
          })
          const asset = new THREE.Group()
          asset.name = 'SEC360 open office floor asset'
          document.meshes.forEach((meshEntry: any) => {
            meshEntry.primitives.forEach((primitive: any) => {
              const geometry = new THREE.BufferGeometry()
              geometry.setAttribute('position', new THREE.BufferAttribute(readAccessor(primitive.attributes.POSITION), 3))
              geometry.setAttribute('normal', new THREE.BufferAttribute(readAccessor(primitive.attributes.NORMAL), 3))
              geometry.setIndex(new THREE.BufferAttribute(readAccessor(primitive.indices), 1))
              geometry.computeBoundingSphere()
              const loadedMaterial = loadedMaterials[primitive.material]
              const mesh = new THREE.Mesh(geometry, loadedMaterial)
              mesh.name = loadedMaterial?.name || meshEntry.name || ''
              mesh.castShadow = mesh.name !== 'Blue curtain glass'
              mesh.receiveShadow = true
              asset.add(mesh)
            })
          })
          return asset
        }

        let floorAssetTemplate: any = null
        try {
          floorAssetTemplate = await loadGlbAsset('/assets/network-map/open-office-floor.glb')
        } catch (assetError) {
          console.error('Network Map floor asset failed to load; using procedural fallback', assetError)
        }

        const random = seededRandom(360)
        const cityMaterial = new THREE.MeshStandardMaterial({ color: 0x07111d, roughness: 0.94, metalness: 0.05 })
        const cityGlow = new THREE.MeshBasicMaterial({ color: 0x0d3a4b, transparent: true, opacity: 0.2 })
        for (let i = 0; i < 66; i += 1) {
          const angle = random() * Math.PI * 2
          const radius = 27 + random() * 52
          const width = 2 + random() * 5
          const depth = 2 + random() * 5
          const height = 1 + Math.pow(random(), 2) * 12
          const x = Math.cos(angle) * radius
          const z = Math.sin(angle) * radius
          addBox(proceduralEnvironment, [width, height, depth], [x, height / 2 - 1.2, z], cityMaterial).castShadow = false
          if (i % 3 === 0) addBox(proceduralEnvironment, [width * 0.72, 0.04, 0.04], [x, height * 0.58, z + depth / 2], cityGlow).castShadow = false
        }
        const ground = new THREE.Mesh(new THREE.CircleGeometry(92, 96), new THREE.MeshStandardMaterial({ color: 0x020711, roughness: 0.95 }))
        ground.rotation.x = -Math.PI / 2
        ground.position.y = -1.22
        ground.receiveShadow = true
        proceduralEnvironment.add(ground)
        const grid = new THREE.GridHelper(138, 60, 0x0e4254, 0x09202d)
        grid.position.y = -1.18
        grid.material.transparent = true
        grid.material.opacity = 0.17
        proceduralEnvironment.add(grid)

        const tower = new THREE.Group()
        tower.position.set(-8.8, 0, 0.6)
        tower.rotation.y = -0.08
        proceduralEnvironment.add(tower)
        const structural = new THREE.MeshStandardMaterial({ color: 0xa9bcc7, metalness: 0.68, roughness: 0.27 })
        const darkGlass = new THREE.MeshPhysicalMaterial({ color: 0x061725, metalness: 0.36, roughness: 0.2, transparent: true, opacity: 0.9, clearcoat: 0.8 })
        // A stepped illuminated podium and the split-wing shell reproduce the supplied tower,
        // instead of treating the building as a generic rectangular stack.
        addBox(tower, [13.2, 0.32, 9.6], [0.2, -0.92, 0.35], structural)
        addBox(tower, [12.6, 0.78, 9.1], [0.2, -0.48, 0.35], darkGlass)
        addBox(tower, [11.4, 0.16, 8.2], [0, -0.02, 0.1], structural)
        const podiumGlow = new THREE.MeshBasicMaterial({ color: 0xffd7a1, transparent: true, opacity: 0.2 })
        for (const x of [-4.8, -3.2, -1.6, 0, 1.6, 3.2, 4.8]) addBox(tower, [0.045, 0.62, 0.04], [x, -0.48, 4.92], podiumGlow).castShadow = false

        const floorStep = 0.76
        const towerHeight = propsRef.current.floors.length * floorStep
        const floorMeshes = new Map<string, { meshes: any[]; glows: any[]; floor: MapFloor }>()
        propsRef.current.floors.forEach((floor, index) => {
          const y = 0.18 + index * floorStep
          const progress = index / Math.max(propsRef.current.floors.length - 1, 1)
          const taper = 1 - progress * 0.075
          const bow = Math.sin(progress * Math.PI) * 0.22
          const leftWidth = 5.45 * taper
          const rightWidth = 4.65 * taper
          const depth = (7.1 + bow) * taper
          const makeWing = (width: number, x: number, rotation: number, z: number) => {
            const material = new THREE.MeshPhysicalMaterial({ color: 0x102b3d, metalness: 0.3, roughness: 0.14, transparent: true, opacity: 0.88, clearcoat: 0.82, clearcoatRoughness: 0.16 })
            const mesh = addBox(tower, [width, 0.64, depth], [x, y + 0.3, z], material)
            mesh.rotation.y = rotation
            mesh.userData = { type: 'floor', id: floor.id }
            interactive.push(mesh)
            return mesh
          }
          const left = makeWing(leftWidth, -2.55 * taper, -0.045, 0)
          const right = makeWing(rightWidth, 2.35 * taper, 0.075, -0.18)
          const seamMaterial = darkGlass.clone()
          seamMaterial.color.setHex(0x020b13)
          const seam = addBox(tower, [0.78, 0.66, depth - 0.28], [0.1, y + 0.3, -0.3], seamMaterial)
          seam.userData = { type: 'floor', id: floor.id }
          interactive.push(seam)
          const glowMaterial = new THREE.MeshBasicMaterial({ color: 0x16e4ef, transparent: true, opacity: 0.08 })
          const leftGlow = addBox(tower, [leftWidth + 0.08, 0.035, depth + 0.12], [-2.55 * taper, y, 0], glowMaterial)
          leftGlow.rotation.y = -0.045
          leftGlow.castShadow = false
          const rightGlow = addBox(tower, [rightWidth + 0.08, 0.035, depth + 0.12], [2.35 * taper, y, -0.18], glowMaterial.clone())
          rightGlow.rotation.y = 0.075
          rightGlow.castShadow = false
          floorMeshes.set(floor.id, { meshes: [left, right, seam], glows: [leftGlow, rightGlow], floor })
        })
        const crownY = 0.18 + towerHeight
        // Continuous white rails are the strongest recognizable feature in the reference.
        for (const [x, z, lean] of [[-5.18, 0.18, -0.025], [5.02, -0.18, 0.025], [-0.48, 3.45, -0.008], [0.72, 3.25, 0.008]] as const) {
          const rail = addBox(tower, [0.1, towerHeight + 3.5, 0.2], [x, towerHeight / 2 + 1.25, z], structural)
          rail.rotation.z = lean
        }
        // Dense vertical mullions make the glass facade read as the real building at overview scale.
        for (const x of [-4.25, -3.15, -2.05, 1.55, 2.55, 3.55, 4.45]) {
          addBox(tower, [0.035, towerHeight, 0.04], [x, towerHeight / 2 + 0.18, 3.55 - Math.abs(x) * 0.035], structural).castShadow = false
        }
        // Split asymmetric crown: the front wing rises higher and the return wing steps down.
        const leftCrown = addBox(tower, [5.2, 1.28, 6.65], [-2.4, crownY + 0.56, -0.02], darkGlass.clone())
        leftCrown.rotation.y = -0.045
        const rightCrown = addBox(tower, [4.35, 0.72, 6.25], [2.3, crownY + 0.28, -0.22], darkGlass.clone())
        rightCrown.rotation.y = 0.075
        for (const [x, height] of [[-5.15, 3.1], [-0.5, 3.6], [0.75, 3.2], [5.0, 2.75]] as const) {
          const fin = addBox(tower, [0.12, height, 0.34], [x, crownY + height / 2, x > 0 ? -0.15 : 0.1], structural)
          fin.rotation.z = x < 0 ? -0.018 : 0.018
        }
        // The photographic plate owns building interaction; WebGL raycasting is reserved
        // for live devices on the extracted floor.
        interactive = []

        const slabMaterial = () => new THREE.MeshStandardMaterial({ color: 0x8da2ae, metalness: 0.12, roughness: 0.46, transparent: true })
        const wallMaterial = () => new THREE.MeshPhysicalMaterial({ color: 0xb9d3dc, transparent: true, opacity: 0.68, roughness: 0.44, side: THREE.DoubleSide })
        const accentMaterial = () => new THREE.MeshBasicMaterial({ color: 0x16e4ef, transparent: true, opacity: 0.82 })
        const addFloorPlan = (parent: any) => {
          const wall = wallMaterial()
          const glass = new THREE.MeshPhysicalMaterial({ color: 0x76c5e8, metalness: 0.08, roughness: 0.16, transmission: 0.36, transparent: true, opacity: 0.48, clearcoat: 0.8, side: THREE.DoubleSide })
          const workFloor = new THREE.MeshStandardMaterial({ color: 0x315f76, emissive: 0x071d29, emissiveIntensity: 0.28, roughness: 0.8, metalness: 0.04 })
          const meetingFloor = new THREE.MeshStandardMaterial({ color: 0x8a6135, emissive: 0x402000, emissiveIntensity: 0.34, roughness: 0.74, metalness: 0.02 })
          const loungeFloor = new THREE.MeshStandardMaterial({ color: 0x496a56, emissive: 0x102a18, emissiveIntensity: 0.26, roughness: 0.82, metalness: 0.01 })
          const serverFloor = new THREE.MeshStandardMaterial({ color: 0x173a68, emissive: 0x061d4e, emissiveIntensity: 0.44, roughness: 0.58, metalness: 0.18 })
          const coreFloor = new THREE.MeshStandardMaterial({ color: 0x3d4a55, roughness: 0.8, metalness: 0.08 })
          const corridorFloor = new THREE.MeshStandardMaterial({ color: 0x82909a, roughness: 0.84, metalness: 0.02 })
          const paleWood = new THREE.MeshStandardMaterial({ color: 0xb98e5d, roughness: 0.64, metalness: 0.02 })
          const charcoal = new THREE.MeshStandardMaterial({ color: 0x17232d, roughness: 0.52, metalness: 0.3 })
          const upholstery = new THREE.MeshStandardMaterial({ color: 0x6f8792, roughness: 0.9, metalness: 0 })
          const plant = new THREE.MeshStandardMaterial({ color: 0x4ca16d, roughness: 0.88, metalness: 0 })
          const porcelain = new THREE.MeshStandardMaterial({ color: 0xd9e5e7, roughness: 0.3, metalness: 0.02 })
          const serverGlow = new THREE.MeshStandardMaterial({ color: 0x132331, emissive: 0x0878d8, emissiveIntensity: 1.65, roughness: 0.32, metalness: 0.62 })
          const floorTile = new THREE.MeshStandardMaterial({ color: 0xaeb9c1, roughness: 0.72, metalness: 0.03 })
          const whiteStructure = new THREE.MeshStandardMaterial({ color: 0xdce6e9, roughness: 0.38, metalness: 0.08 })
          const warmPanel = new THREE.MeshStandardMaterial({ color: 0xffe2b5, emissive: 0xffa43b, emissiveIntensity: 1.35, roughness: 0.3, metalness: 0.04 })

          const addZone = (width: number, depth: number, x: number, z: number, material: any, elevation = 0.2) => {
            const zone = addBox(parent, [width, 0.055, depth], [x, elevation, z], material)
            zone.castShadow = false
            return zone
          }
          const addWall = (width: number, depth: number, x: number, z: number, material = wall, height = 0.78) =>
            addBox(parent, [width, height, depth], [x, 0.22 + height / 2, z], material)
          const addChair = (group: any, x: number, z: number, rotation = 0) => {
            const chair = new THREE.Group()
            chair.position.set(x, 0, z)
            chair.rotation.y = rotation
            addBox(chair, [0.32, 0.12, 0.32], [0, 0.34, 0], charcoal)
            addBox(chair, [0.32, 0.42, 0.09], [0, 0.54, 0.13], charcoal)
            group.add(chair)
          }
          const addDeskCluster = (x: number, z: number, rotation = 0) => {
            const group = new THREE.Group()
            group.position.set(x, 0, z)
            group.rotation.y = rotation
            addBox(group, [1.62, 0.11, 0.76], [0, 0.58, 0], paleWood)
            addBox(group, [0.06, 0.48, 0.62], [-0.67, 0.36, 0], charcoal)
            addBox(group, [0.06, 0.48, 0.62], [0.67, 0.36, 0], charcoal)
            for (const dx of [-0.4, 0.4]) {
              for (const dz of [-0.5, 0.5]) addChair(group, dx, dz, dz > 0 ? Math.PI : 0)
              addBox(group, [0.42, 0.28, 0.035], [dx, 0.83, 0], charcoal).rotation.x = -0.08
            }
            parent.add(group)
          }
          const addMeetingTable = (x: number, z: number, width: number, rotation = 0) => {
            const group = new THREE.Group()
            group.position.set(x, 0, z)
            group.rotation.y = rotation
            addBox(group, [width, 0.12, 0.78], [0, 0.55, 0], paleWood)
            addBox(group, [width * 0.72, 0.44, 0.12], [0, 0.31, 0], charcoal)
            const seats = Math.max(2, Math.floor(width / 0.55))
            for (let i = 0; i < seats; i += 1) {
              const seatX = -width / 2 + 0.34 + i * ((width - 0.68) / Math.max(seats - 1, 1))
              addChair(group, seatX, -0.62, 0)
              addChair(group, seatX, 0.62, Math.PI)
            }
            parent.add(group)
          }
          const addCafeTable = (x: number, z: number) => {
            const group = new THREE.Group()
            group.position.set(x, 0, z)
            const top = new THREE.Mesh(new THREE.CylinderGeometry(0.46, 0.46, 0.1, 24), paleWood)
            top.position.y = 0.57
            top.castShadow = true
            group.add(top)
            const stem = new THREE.Mesh(new THREE.CylinderGeometry(0.08, 0.14, 0.5, 12), charcoal)
            stem.position.y = 0.3
            group.add(stem)
            for (let i = 0; i < 4; i += 1) {
              const angle = i * Math.PI / 2
              addChair(group, Math.cos(angle) * 0.72, Math.sin(angle) * 0.72, -angle + Math.PI / 2)
            }
            parent.add(group)
          }
          const addPlanter = (x: number, z: number) => {
            const pot = new THREE.Mesh(new THREE.CylinderGeometry(0.19, 0.25, 0.32, 14), charcoal)
            pot.position.set(x, 0.37, z)
            pot.castShadow = true
            parent.add(pot)
            const leaves = new THREE.Mesh(new THREE.DodecahedronGeometry(0.34, 0), plant)
            leaves.scale.set(0.85, 1.25, 0.85)
            leaves.position.set(x, 0.76, z)
            leaves.castShadow = true
            parent.add(leaves)
          }
          const addServerRack = (x: number, z: number) => {
            const rack = addBox(parent, [0.62, 1.08, 0.62], [x, 0.76, z], charcoal)
            addEdges(parent, rack, 0x2ea8ff, 0.5)
            for (const y of [0.4, 0.59, 0.78, 0.97]) {
              const panel = addBox(parent, [0.48, 0.09, 0.025], [x, y, z + 0.325], serverGlow)
              panel.castShadow = false
            }
          }
          const addSofa = (x: number, z: number, rotation = 0) => {
            const group = new THREE.Group()
            group.position.set(x, 0, z)
            group.rotation.y = rotation
            addBox(group, [1.34, 0.32, 0.62], [0, 0.39, 0], upholstery)
            addBox(group, [1.34, 0.52, 0.16], [0, 0.57, 0.25], upholstery)
            addBox(group, [0.18, 0.4, 0.62], [-0.61, 0.48, 0], upholstery)
            addBox(group, [0.18, 0.4, 0.62], [0.61, 0.48, 0], upholstery)
            parent.add(group)
          }

          // The approved visual is an open operations floor: a pale slab, glass edge,
          // sparse work settings, and one compact service core. Network devices remain
          // the strongest objects in the scene rather than competing with a room grid.
          addZone(22.2, 12.18, 0, 0, floorTile)
          ;[
            [0.11, 0.9, 12.25, -11.08, 0], [0.11, 0.9, 12.25, 11.08, 0],
            [22.2, 0.9, 0.11, 0, -6.03], [22.2, 0.9, 0.11, 0, 6.03],
          ].forEach(([width, height, depth, x, z]) => addWall(width, depth, x, z, glass, height))
          for (const x of [-9.6, -7.2, -4.8, -2.4, 0, 2.4, 4.8, 7.2, 9.6]) {
            addWall(0.045, 0.12, x, -6, structural, 0.9).castShadow = false
            addWall(0.045, 0.12, x, 6, structural, 0.9).castShadow = false
          }
          for (const z of [-4.5, -3, -1.5, 0, 1.5, 3, 4.5]) {
            addWall(0.12, 0.045, -11.05, z, structural, 0.9).castShadow = false
            addWall(0.12, 0.045, 11.05, z, structural, 0.9).castShadow = false
          }

          const addLitColumn = (x: number, z: number) => {
            addBox(parent, [0.42, 1.35, 0.42], [x, 0.89, z], whiteStructure)
            const panel = addBox(parent, [0.12, 0.72, 0.025], [x, 0.91, z + 0.225], warmPanel)
            panel.castShadow = false
          }
          for (const [x, z] of [[-9.2, -4.75], [-5.5, 4.75], [-2.5, -2.9], [3.85, -3.45], [6.6, 3.95], [9.1, -2.5], [9.4, 4.75]] as const) addLitColumn(x, z)

          addZone(5.25, 3.5, 1.4, 0.05, coreFloor, 0.225)
          addWall(5.25, 0.15, 1.4, -1.7, charcoal, 1.08)
          addWall(5.25, 0.15, 1.4, 1.8, charcoal, 1.08)
          addWall(0.15, 3.65, -1.22, 0.05, charcoal, 1.08)
          addWall(0.15, 3.65, 4.02, 0.05, charcoal, 1.08)
          for (const x of [-0.1, 1.15, 2.4]) addWall(0.12, 2.9, x, 0.05, wall, 0.82)
          for (const [x, z] of [[-0.65, -0.95], [0.55, -0.95], [1.8, -0.95], [3.25, -0.95], [-0.65, 1.05], [0.55, 1.05], [1.8, 1.05], [3.25, 1.05]] as const) {
            const fixture = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 0.18, 0.24, 14), porcelain)
            fixture.position.set(x, 0.4, z)
            parent.add(fixture)
          }

          for (const [x, z, rotation] of [
            [-7.8, -3.55, 0], [-6.2, 1.25, 0], [-4.7, 4.05, 0], [5.9, -3.45, 0], [7.75, 0.4, Math.PI / 2], [7.1, 3.95, 0], [9.2, 3.15, Math.PI / 2],
          ] as const) addDeskCluster(x, z, rotation)
          addMeetingTable(-1.9, -4.65, 2.25)
          addBox(parent, [2.8, 0.68, 0.52], [7.9, 0.56, -4.85], paleWood)
          addBox(parent, [1.5, 0.08, 0.62], [7.7, 0.64, -3.95], paleWood)
          for (const [x, z] of [[-9.9, -4.9], [-8.7, 4.9], [-4.2, -4.85], [4.7, -4.85], [5.05, 4.8], [9.8, -4.65], [9.75, 4.85]] as const) addPlanter(x, z)

          // Kept as a dormant layout option for customers that later choose to import
          // the full architectural room plan instead of the approved open-floor style.
          const architecturalRooms = false
          if (architecturalRooms) {
          // Glazed perimeter with a deliberately lower cutaway edge for a legible 2.5D plan.
          ;[
            [0.14, 0.98, 12.7, -11.25, 0], [0.14, 0.98, 12.7, 11.25, 0],
            [22.65, 0.98, 0.14, 0, -6.28], [22.65, 0.98, 0.14, 0, 6.28],
          ].forEach(([width, height, depth, x, z]) => addWall(width, depth, x, z, glass, height))

          // Functional color zones follow the supplied plan without exposing team or room names.
          addZone(21.9, 2.2, 0, -4.95, workFloor)
          addZone(21.9, 2.2, 0, 4.95, workFloor)
          addZone(2.35, 7.2, -10, 0, workFloor)
          addZone(2.45, 3.7, 9.95, -2.05, workFloor)
          addZone(4.25, 4.15, 8.65, 2.05, loungeFloor)
          addZone(3.75, 2.4, -4.55, 0.9, serverFloor)
          addZone(3.1, 2.45, -4.8, -1.95, serverFloor)
          addZone(6.75, 4.45, 1.65, 0.3, coreFloor)
          addZone(12.3, 1.25, 2.25, -2.95, corridorFloor)
          addZone(13.2, 1.2, 1.75, 3.05, corridorFloor)

          // Long perimeter office bands and their room divisions.
          addWall(19.3, 0.13, -0.7, -3.78)
          addWall(19.3, 0.13, -0.7, 3.78)
          for (const x of [-8.25, -6.1, -3.75, -1.15, 1.55, 4.35, 6.85, 8.8]) {
            addWall(0.13, 2.5, x, -5.02)
            addWall(0.13, 2.5, x, 5.02)
          }
          addWall(0.13, 7.6, -8.78, 0)
          for (const z of [-2.45, 0.15, 2.55]) addWall(2.5, 0.13, -10.02, z)
          addWall(0.13, 3.5, 8.72, -1.95)
          addWall(2.55, 0.13, 9.98, -0.15)

          // Meeting rooms have warm flooring and fewer, larger tables.
          for (const [x, z, width, depth] of [[-7.15, -4.96, 2.05, 2.18], [-2.45, -4.96, 2.45, 2.18], [2.95, -4.96, 2.65, 2.18], [7.8, 4.96, 1.85, 2.18]] as const) {
            addZone(width, depth, x, z, meetingFloor, 0.23)
            addMeetingTable(x, z, width > 2.3 ? 1.5 : 1.15)
          }

          // Workstations form compact bench neighborhoods around the perimeter.
          for (const [x, z, rotation] of [
            [-9.92, -4.85, Math.PI / 2], [-5, -4.92, 0], [0.2, -4.92, 0], [5.45, -4.92, 0], [9.85, -4.85, Math.PI / 2],
            [-9.92, -1.25, Math.PI / 2], [-9.92, 1.55, Math.PI / 2], [-8.25, 4.92, 0], [-5, 4.92, 0], [-0.05, 4.92, 0], [3.1, 4.92, 0], [5.85, 4.92, 0],
          ] as const) addDeskCluster(x, z, rotation)

          // Central service core: elevators, two stairs, restrooms and paired server rooms.
          addWall(6.8, 0.14, 1.75, -1.95)
          addWall(6.8, 0.14, 1.75, 2.5)
          addWall(0.14, 4.58, -1.65, 0.28)
          addWall(0.14, 4.58, 5.15, 0.28)
          for (const x of [0.15, 1.2, 2.3, 3.35]) {
            addBox(parent, [0.82, 1.16, 0.68], [x, 0.8, 0.15], charcoal)
            addBox(parent, [0.58, 0.9, 0.025], [x, 0.76, 0.505], structural.clone())
          }
          for (const x of [-0.78, 4.3]) {
            addWall(1.45, 1.55, x, 1.55, charcoal, 1.18)
            for (let step = 0; step < 5; step += 1) addBox(parent, [1.15, 0.08, 0.2], [x, 0.3 + step * 0.13, 1.1 + step * 0.2], structural.clone())
          }
          for (const x of [-0.75, 0.1]) {
            addWall(0.08, 1.3, x, -1.02, wall, 0.72)
            const basin = new THREE.Mesh(new THREE.CylinderGeometry(0.18, 0.22, 0.25, 16), porcelain)
            basin.position.set(x - 0.36, 0.36, -1.1)
            parent.add(basin)
          }
          for (const [x, z] of [[-5.5, -2.15], [-4.65, -2.15], [-5.5, 0.75], [-4.65, 0.75], [-3.8, 0.75]] as const) addServerRack(x, z)

          // Kitchen, café, and lounge occupy the large right-hand social zone.
          addBox(parent, [3.2, 0.72, 0.58], [9.1, 0.58, 0.32], paleWood)
          addBox(parent, [2.25, 0.1, 0.7], [8.82, 0.62, 1.22], paleWood)
          for (const x of [7.95, 8.55, 9.15, 9.75]) addChair(parent, x, 1.82, Math.PI)
          addCafeTable(8.0, 2.65)
          addCafeTable(9.75, 3.55)
          addSofa(7.55, 4.45, -0.12)
          addSofa(9.25, 4.65, Math.PI + 0.14)
          addBox(parent, [1.1, 0.12, 0.56], [8.45, 0.46, 4.35], paleWood)

          // Small collaboration pocket inside the circulation ring.
          addSofa(-1.5, -2.82, Math.PI / 2)
          addSofa(0.15, -2.82, -Math.PI / 2)
          addBox(parent, [0.72, 0.11, 0.46], [-0.68, 0.43, -2.82], paleWood)
          for (const [x, z] of [[-10.6, -5.65], [-8.95, 5.65], [-5.95, -3.38], [4.82, -3.35], [7.05, 2.5], [10.65, 4.95], [6.65, 5.65], [3.95, -5.65]] as const) addPlanter(x, z)
          }
        }

        type Detail = { group: any; floorId: string; opacity: number; leaving: boolean; interactive: any[]; born: number }
        let details: Detail[] = []
        let activeFloorId: string | null = null
        let detailSignature = ''
        let cameraTransitionUntil = 0

        const buildDetail = (floor: MapFloor, now: number) => {
          details.forEach(detail => { detail.leaving = true })
          pulses = []
          rings = []
          const group = new THREE.Group()
          group.position.set(-8.8, 0.18 + (floor.ordinal - 1) * floorStep, 0.6)
          group.scale.setScalar(reduceMotion ? 1 : 0.52)
          world.add(group)
          const localInteractive: any[] = []
          if (floorAssetTemplate) {
            const floorModel = floorAssetTemplate.clone(true)
            floorModel.traverse((object: any) => {
              if (!object.isMesh) return
              object.geometry = object.geometry.clone()
              object.material = object.material.clone()
            })
            group.add(floorModel)
            const outline = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(22.7, 0.44, 12.7)), new THREE.LineBasicMaterial({ color: 0x69eaf4, transparent: true, opacity: 0.64 }))
            outline.position.y = -0.22
            group.add(outline)
          } else {
            const slab = addBox(group, [22.7, 0.34, 12.7], [0, 0, 0], slabMaterial())
            addEdges(group, slab, 0x5cebf1, 0.78)
            addFloorPlan(group)
            const floorGrid = new THREE.GridHelper(22.3, 24, 0xaec2cc, 0x718792)
            floorGrid.scale.z = 0.56
            floorGrid.position.y = 0.232
            floorGrid.material.transparent = true
            floorGrid.material.opacity = 0.34
            group.add(floorGrid)
          }
          const floorLight = new THREE.PointLight(0xbfefff, 13, 28, 2)
          floorLight.position.set(0, 7, 0)
          group.add(floorLight)
          // Small pools of light make the functional zones read like the rendered
          // reference while keeping fixtures and live network overlays unobstructed.
          for (const [x, z] of [[-7.15, -4.96], [-2.45, -4.96], [2.95, -4.96], [7.8, 4.96]] as const) {
            const meetingLight = new THREE.PointLight(0xffbd72, 3.2, 4.2, 2)
            meetingLight.position.set(x, 2.1, z)
            group.add(meetingLight)
          }
          const socialLight = new THREE.PointLight(0xc4e8a6, 3.5, 5.5, 2)
          socialLight.position.set(8.7, 2.4, 2.3)
          group.add(socialLight)
          const serverLight = new THREE.PointLight(0x237dff, 3.6, 4.8, 2)
          serverLight.position.set(-4.8, 2.2, -0.6)
          group.add(serverLight)

          const state = propsRef.current
          const floorEquipment = floor.managed ? state.equipment.filter(item => item.floor_id === floor.id) : []
          floorEquipment.forEach(item => {
            const x = THREE.MathUtils.clamp(item.position.x, -9.5, 9.5)
            const z = THREE.MathUtils.clamp(item.position.z, -5.4, 5.4)
            const device = new THREE.Group()
            device.position.set(x, 0.28, z)
            device.userData = { type: 'equipment', id: item.id }
            group.add(device)
            if (item.kind === 'ap') {
              const body = new THREE.Mesh(new THREE.CylinderGeometry(0.65, 0.73, 0.2, 40), new THREE.MeshPhysicalMaterial({ color: 0xe5f3f6, roughness: 0.24, metalness: 0.12, clearcoat: 0.9 }))
              body.position.y = 0.35
              body.userData = device.userData
              body.castShadow = true
              device.add(body)
              localInteractive.push(body)
              const cap = new THREE.Mesh(new THREE.TorusGeometry(0.22, 0.025, 8, 40), accentMaterial())
              cap.rotation.x = Math.PI / 2
              cap.position.y = 0.45
              device.add(cap)
              for (let ringIndex = 0; ringIndex < 3; ringIndex += 1) {
                const ring = new THREE.Mesh(new THREE.RingGeometry(0.62, 0.66, 48), new THREE.MeshBasicMaterial({ color: 0x20e8f3, transparent: true, opacity: 0.22, side: THREE.DoubleSide, depthWrite: false }))
                ring.rotation.x = -Math.PI / 2
                ring.position.y = 0.22
                device.add(ring)
                rings.push({ mesh: ring, phase: ringIndex / 3 + floorEquipment.indexOf(item) * 0.13 })
              }
            } else {
              const body = addBox(device, [1.35, 0.38, 0.72], [0, 0.28, 0], darkGlass.clone())
              body.userData = device.userData
              localInteractive.push(body)
            }
            const label = makeLabel(item.name, item.id === state.selectedEquipmentId)
            label.position.set(0, 1.55, 0)
            device.add(label)
            state.attachments.filter(row => row.equipment_id === item.id).slice(0, 32).forEach((row, index) => {
              const angle = index / Math.max(state.attachments.length, 1) * Math.PI * 2 + (index % 2) * 0.28
              const radius = 1.65 + (index % 5) * 0.53
              const position = new THREE.Vector3(THREE.MathUtils.clamp(x + Math.cos(angle) * radius, -9.6, 9.6), 0.38, THREE.MathUtils.clamp(z + Math.sin(angle) * radius, -5.25, 5.25))
              const material = new THREE.MeshStandardMaterial({ color: row.match_state === 'matched' ? 0x55e6cf : row.match_state === 'ambiguous' ? 0xf3b85b : 0x708393, emissive: row.id === state.selectedAttachmentId ? 0x1bd7df : 0x071018, emissiveIntensity: row.id === state.selectedAttachmentId ? 2.4 : 0.5, metalness: 0.35, roughness: 0.35 })
              const endpoint = new THREE.Group()
              endpoint.position.copy(position)
              const base = addBox(endpoint, [0.58, 0.06, 0.4], [0, 0, 0], material)
              base.userData = { type: 'attachment', id: row.id }
              localInteractive.push(base)
              const screen = addBox(endpoint, [0.56, 0.4, 0.055], [0, 0.24, -0.13], material)
              screen.rotation.x = -0.16
              screen.userData = base.userData
              localInteractive.push(screen)
              group.add(endpoint)
              const startPoint = new THREE.Vector3(x, 0.57, z)
              const midpoint = startPoint.clone().lerp(position, 0.5).setY(0.82)
              const curve = new THREE.QuadraticBezierCurve3(startPoint, midpoint, position.clone().setY(0.48))
              const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(24)), row.attachment_type === 'wireless' ? new THREE.LineDashedMaterial({ color: 0x20dceb, dashSize: 0.2, gapSize: 0.13, transparent: true, opacity: 0.56 }) : new THREE.LineBasicMaterial({ color: 0x2ce0bd, transparent: true, opacity: 0.62 }))
              if (row.attachment_type === 'wireless') line.computeLineDistances()
              group.add(line)
              const pulse = new THREE.Mesh(new THREE.SphereGeometry(0.1, 12, 12), new THREE.MeshBasicMaterial({ color: row.attachment_type === 'wireless' ? 0x7ff5ff : 0x72ffd8 }))
              group.add(pulse)
              pulses.push({ mesh: pulse, curve, phase: index / Math.max(1, floorEquipment.length), speed: 0.16 + (index % 4) * 0.025 })
            })
          })
          const detail = { group, floorId: floor.id, opacity: reduceMotion ? 1 : 0, leaving: false, interactive: localInteractive, born: now }
          details.push(detail)
          interactive = localInteractive
          activeFloorId = floor.id
          cameraTransitionUntil = now + (reduceMotion ? 0 : 1.25)
        }

        const raycaster = new THREE.Raycaster()
        const pointer = new THREE.Vector2()
        let downX = 0
        let downY = 0
        let hovered: any = null
        const setPointer = (event: PointerEvent) => {
          const rect = renderer.domElement.getBoundingClientRect()
          pointer.set(((event.clientX - rect.left) / rect.width) * 2 - 1, -((event.clientY - rect.top) / rect.height) * 2 + 1)
          raycaster.setFromCamera(pointer, camera)
        }
        const onPointerDown = (event: PointerEvent) => { downX = event.clientX; downY = event.clientY }
        const onPointerMove = (event: PointerEvent) => {
          setPointer(event)
          const hit = raycaster.intersectObjects(interactive, false)[0]?.object || null
          hovered = hit
            renderer.domElement.style.cursor = hovered ? 'pointer' : 'default'
        }
        const onPointerUp = (event: PointerEvent) => {
          if (Math.hypot(event.clientX - downX, event.clientY - downY) > 7) return
          setPointer(event)
          const hit = raycaster.intersectObjects(interactive, false)[0]?.object
          if (hit?.userData.type === 'floor') propsRef.current.onSelectFloor(hit.userData.id)
          if (hit?.userData.type === 'equipment') propsRef.current.onSelectEquipment(hit.userData.id)
          if (hit?.userData.type === 'attachment') propsRef.current.onSelectAttachment(hit.userData.id)
        }
        renderer.domElement.addEventListener('pointerdown', onPointerDown)
        renderer.domElement.addEventListener('pointermove', onPointerMove)
        renderer.domElement.addEventListener('pointerup', onPointerUp)

        const resize = () => {
          const width = host.clientWidth
          const height = host.clientHeight
          renderer.setSize(width, height)
          camera.aspect = width / Math.max(height, 1)
          camera.updateProjectionMatrix()
        }
        observer = new ResizeObserver(resize)
        observer.observe(host)
        resize()

        const clock = new THREE.Clock()
        const animate = () => {
          frame = requestAnimationFrame(animate)
          const delta = Math.min(clock.getDelta(), 0.05)
          const elapsed = clock.elapsedTime
          const state = propsRef.current
          const selected = state.floors.find(floor => floor.id === state.selectedFloorId) || null
          const signature = selected ? `${selected.id}:${state.selectedEquipmentId || ''}:${state.selectedAttachmentId || ''}:${state.equipment.filter(item => item.floor_id === selected.id).length}:${state.attachments.filter(item => item.floor_id === selected.id).length}` : ''
          if (selected && (activeFloorId !== selected.id || signature !== detailSignature)) {
            buildDetail(selected, elapsed)
            detailSignature = signature
          } else if (!selected && activeFloorId) {
            details.forEach(detail => { detail.leaving = true })
            activeFloorId = null
            detailSignature = ''
            interactive = []
            cameraTransitionUntil = elapsed + (reduceMotion ? 0 : 1.1)
          }

          const smooth = (speed: number) => reduceMotion ? 1 : 1 - Math.exp(-speed * delta)
          details.forEach(detail => {
            const target = detail.leaving ? new THREE.Vector3(16.5, 7, -1.8) : new THREE.Vector3(9.75, 7.55, -0.35)
            detail.group.position.lerp(target, smooth(detail.leaving ? 5.5 : 4.2))
            const scale = detail.leaving ? 1.02 : 1.12
            detail.group.scale.lerp(new THREE.Vector3(scale, scale, scale), smooth(5.2))
            detail.opacity += ((detail.leaving ? 0 : 1) - detail.opacity) * smooth(detail.leaving ? 6.5 : 5.5)
            setGroupOpacity(detail.group, detail.opacity)
          })
          details.filter(detail => detail.leaving && detail.opacity < 0.015).forEach(detail => disposeGroup(detail.group))
          details = details.filter(detail => !(detail.leaving && detail.opacity < 0.015))

          const targetLook = activeFloorId ? detailLook : overviewLook
          controls.target.lerp(targetLook, smooth(4.2))
          if (elapsed < cameraTransitionUntil) camera.position.lerp(activeFloorId ? detailPosition : overviewPosition, smooth(3.4))
          if (!reduceMotion) {
            rings.forEach(({ mesh, phase }) => {
              const cycle = (elapsed * 0.42 + phase) % 1
              mesh.scale.setScalar(0.86 + cycle * 1.35)
              mesh.material.opacity = (1 - cycle) * 0.28
            })
            pulses.forEach(({ mesh, curve, phase, speed }) => mesh.position.copy(curve.getPoint((elapsed * speed + phase) % 1)))
            cyanLight.intensity = 70 + Math.sin(elapsed * 0.8) * 7
          }
          controls.update()
          renderer.render(scene, camera)
        }
        animate()

        cleanup = () => {
          cancelAnimationFrame(frame)
          renderer.domElement.removeEventListener('pointerdown', onPointerDown)
          renderer.domElement.removeEventListener('pointermove', onPointerMove)
          renderer.domElement.removeEventListener('pointerup', onPointerUp)
          controls.dispose()
          scene.traverse((object: any) => {
            object.geometry?.dispose?.()
            const materials = Array.isArray(object.material) ? object.material : object.material ? [object.material] : []
            materials.forEach((material: any) => { material.map?.dispose?.(); material.dispose?.() })
          })
          renderer.dispose()
          renderer.domElement.remove()
        }
      } catch (error) {
        console.error('Network Map WebGL initialization failed', error)
        if (!disposed) setFailed(true)
      }
    }
    start()
    return () => { disposed = true; observer?.disconnect(); cleanup() }
  }, [failed])

  const selectedFloor = props.floors.find(floor => floor.id === props.selectedFloorId)
  const guideTop = selectedFloor ? 84.6 - ((selectedFloor.ordinal - 1) / 30) * 75 : 50

  return <div className="relative h-full w-full overflow-hidden bg-[#030913]" aria-label="Interactive 31-floor Network Map">
    <div
      className={`absolute inset-0 z-0 transition-[transform,filter] duration-1000 ease-[cubic-bezier(.22,1,.36,1)] motion-reduce:transition-none ${selectedFloor ? 'brightness-[.78] saturate-[.9]' : 'brightness-100 saturate-100'}`}
      style={{ transform: selectedFloor ? 'translate3d(-17%, 0, 0) scale(1.045)' : 'translate3d(0, 0, 0) scale(1)' }}
    >
      <img src="/assets/network-map/building-night.png" alt="" className="pointer-events-none absolute inset-0 h-full w-full select-none object-cover object-center" />
    </div>
    <div className="pointer-events-none absolute inset-0 z-[5] transition-transform duration-1000 ease-[cubic-bezier(.22,1,.36,1)] motion-reduce:transition-none" style={{ transform: selectedFloor ? 'translate3d(-17%, 0, 0) scale(1.045)' : 'translate3d(0, 0, 0) scale(1)' }}>
      <div className="absolute bottom-[13.2%] left-[26.25%] top-[8.6%] z-[5] grid w-[13.9%] grid-rows-[repeat(31,minmax(0,1fr))]">
        {props.floors.slice().reverse().map(floor => {
          const selected = floor.id === props.selectedFloorId
          return <button
            key={floor.id}
            onClick={() => props.onSelectFloor(floor.id)}
            aria-label={`Open ${floor.label}, floor ${floor.ordinal}`}
            title={`${floor.ordinal} · ${floor.label}${floor.managed ? '' : ' · available'}`}
            className={`pointer-events-auto group relative w-full border-y transition-[background-color,border-color,box-shadow,transform] duration-300 focus-visible:z-10 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-200 ${selected ? 'z-10 scale-x-[1.045] border-cyan-100 bg-cyan-300/45 shadow-[0_0_28px_rgba(34,211,238,.72)]' : floor.managed ? 'border-cyan-300/15 bg-cyan-300/[0.045] hover:border-cyan-200/55 hover:bg-cyan-300/20' : 'border-transparent bg-transparent hover:border-white/25 hover:bg-white/[0.06]'}`}
          ><span className={`pointer-events-none absolute -right-9 top-1/2 -translate-y-1/2 text-[8px] font-semibold tabular-nums transition-opacity ${selected ? 'text-cyan-100 opacity-100' : 'text-slate-500 opacity-0 group-hover:opacity-100'}`}>{String(floor.ordinal).padStart(2, '0')}</span></button>
        })}
      </div>
    </div>
    {selectedFloor && <svg className="pointer-events-none absolute inset-0 z-[3] h-full w-full overflow-visible" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id="floor-guide" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#67f7ff" stopOpacity=".95" />
          <stop offset="1" stopColor="#22d3ee" stopOpacity=".2" />
        </linearGradient>
        <filter id="floor-guide-glow" x="-20%" y="-30%" width="140%" height="160%">
          <feGaussianBlur stdDeviation=".22" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>
      <line x1="22" y1={guideTop} x2="45" y2="33" stroke="url(#floor-guide)" strokeWidth=".18" vectorEffect="non-scaling-stroke" filter="url(#floor-guide-glow)" />
      <line x1="22" y1={guideTop} x2="45" y2="67" stroke="url(#floor-guide)" strokeWidth=".18" vectorEffect="non-scaling-stroke" filter="url(#floor-guide-glow)" />
    </svg>}
    <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_34%_44%,transparent_0%,transparent_27%,rgba(3,9,19,.08)_48%,rgba(3,9,19,.35)_100%)]" />
    <div className={`pointer-events-none absolute inset-0 z-[1] bg-[radial-gradient(ellipse_at_73%_51%,rgba(3,9,19,.76)_0%,rgba(3,9,19,.58)_34%,rgba(3,9,19,.12)_64%,transparent_80%)] transition-opacity duration-1000 ease-[cubic-bezier(.22,1,.36,1)] motion-reduce:transition-none ${selectedFloor ? 'opacity-100' : 'opacity-0'}`} />
    {!failed && <div ref={hostRef} className="absolute inset-0 z-[2] h-full w-full" />}
    {failed && <div className="absolute right-[8%] top-1/2 z-[3] -translate-y-1/2 text-center"><p className="text-sm font-medium text-zinc-300">Live floor rendering is unavailable</p><p className="mt-1 text-xs text-zinc-600">The building and floor directory remain available.</p></div>}
  </div>
}
