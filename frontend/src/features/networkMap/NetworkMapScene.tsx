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
        scene.background = new THREE.Color(0x030913)
        scene.fog = new THREE.FogExp2(0x030913, 0.013)

        const camera = new THREE.PerspectiveCamera(33, 1, 0.1, 260)
        const overviewPosition = new THREE.Vector3(31, 22, 50)
        const detailPosition = new THREE.Vector3(31, 20, 43)
        const overviewLook = new THREE.Vector3(-2.5, 10.7, 0)
        const detailLook = new THREE.Vector3(1.4, 8.5, 0)
        camera.position.copy(overviewPosition)
        camera.lookAt(overviewLook)

        const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: 'high-performance' })
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
        renderer.outputColorSpace = THREE.SRGBColorSpace
        renderer.toneMapping = THREE.ACESFilmicToneMapping
        renderer.toneMappingExposure = 1.28
        renderer.shadowMap.enabled = true
        renderer.shadowMap.type = THREE.PCFSoftShadowMap
        renderer.domElement.style.touchAction = 'none'
        host.appendChild(renderer.domElement)

        const controls = new OrbitControls(camera, renderer.domElement)
        controls.enableDamping = true
        controls.dampingFactor = 0.065
        controls.enablePan = true
        controls.minDistance = 18
        controls.maxDistance = 82
        controls.minPolarAngle = Math.PI * 0.08
        controls.maxPolarAngle = Math.PI * 0.49
        controls.target.copy(overviewLook)

        scene.add(new THREE.HemisphereLight(0xb4e3ff, 0x02050a, 3.1))
        const key = new THREE.DirectionalLight(0xf0f8ff, 5.4)
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
        const cyanLight = new THREE.PointLight(0x14dbe5, 76, 58, 2)
        cyanLight.position.set(-8, 13, 7)
        scene.add(cyanLight)
        const blueLight = new THREE.PointLight(0x2c72ff, 52, 70, 2)
        blueLight.position.set(15, 14, -14)
        scene.add(blueLight)

        const world = new THREE.Group()
        scene.add(world)
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
          addBox(world, [width, height, depth], [x, height / 2 - 1.2, z], cityMaterial).castShadow = false
          if (i % 3 === 0) addBox(world, [width * 0.72, 0.04, 0.04], [x, height * 0.58, z + depth / 2], cityGlow).castShadow = false
        }
        const ground = new THREE.Mesh(new THREE.CircleGeometry(92, 96), new THREE.MeshStandardMaterial({ color: 0x020711, roughness: 0.95 }))
        ground.rotation.x = -Math.PI / 2
        ground.position.y = -1.22
        ground.receiveShadow = true
        world.add(ground)
        const grid = new THREE.GridHelper(138, 60, 0x0e4254, 0x09202d)
        grid.position.y = -1.18
        grid.material.transparent = true
        grid.material.opacity = 0.17
        world.add(grid)

        const tower = new THREE.Group()
        tower.position.set(-8.8, 0, 0.6)
        tower.rotation.y = -0.08
        world.add(tower)
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

        const slabMaterial = () => new THREE.MeshStandardMaterial({ color: 0x607785, metalness: 0.18, roughness: 0.42, transparent: true })
        const wallMaterial = () => new THREE.MeshPhysicalMaterial({ color: 0xb9d3dc, transparent: true, opacity: 0.58, roughness: 0.52, side: THREE.DoubleSide })
        const accentMaterial = () => new THREE.MeshBasicMaterial({ color: 0x16e4ef, transparent: true, opacity: 0.82 })
        const addFloorPlan = (parent: any) => {
          const wall = wallMaterial()
          const perimeter = [
            [[0.16, 1.05, 12.5], [-10.5, 0.72, 0]], [[0.16, 1.05, 12.5], [10.5, 0.72, 0]],
            [[21.1, 1.05, 0.16], [0, 0.72, -6.15]], [[21.1, 1.05, 0.16], [0, 0.72, 6.15]],
          ] as const
          perimeter.forEach(([size, position]) => addBox(parent, [...size], [...position], wall))
          addBox(parent, [14.5, 0.82, 0.13], [-2.4, 0.6, 3.55], wall)
          addBox(parent, [14.5, 0.82, 0.13], [-2.4, 0.6, -3.65], wall)
          for (const x of [-8.25, -5.9, -3.55, -1.2, 1.15]) {
            addBox(parent, [0.12, 0.82, 2.55], [x, 0.6, 4.83], wall)
            addBox(parent, [0.12, 0.82, 2.35], [x, 0.6, -4.82], wall)
          }
          addBox(parent, [3.05, 1.5, 2.35], [-1.7, 0.9, -0.15], darkGlass.clone())
          addBox(parent, [2.45, 1.5, 2.55], [2.25, 0.9, 0.2], darkGlass.clone())
          for (const x of [-7.1, -4.6, -2.1, 0.4, 5.6, 8.1]) addBox(parent, [1.2, 0.08, 0.52], [x, 0.48, x > 3 ? 2.4 : -2.25], structural.clone()).castShadow = false
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
          const slab = addBox(group, [21.2, 0.34, 12.5], [0, 0, 0], slabMaterial())
          addEdges(group, slab, 0x5cebf1, 0.78)
          addFloorPlan(group)
          const floorGrid = new THREE.GridHelper(20.8, 22, 0x78b5c7, 0x314b5b)
          floorGrid.scale.z = 0.59
          floorGrid.position.y = 0.2
          floorGrid.material.transparent = true
          floorGrid.material.opacity = 0.22
          group.add(floorGrid)
          const floorLight = new THREE.PointLight(0xbfefff, 44, 28, 2)
          floorLight.position.set(0, 7, 0)
          group.add(floorLight)

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
          interactive = [...floorMeshes.values()].flatMap(item => item.meshes).concat(localInteractive)
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
          renderer.domElement.style.cursor = hovered ? 'pointer' : 'grab'
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
            interactive = [...floorMeshes.values()].flatMap(item => item.meshes)
            cameraTransitionUntil = elapsed + (reduceMotion ? 0 : 1.1)
          }

          state.floors.forEach(floor => {
            const visual = floorMeshes.get(floor.id)
            if (!visual) return
            const isSelected = floor.id === state.selectedFloorId
            visual.meshes.forEach(mesh => {
              mesh.material.color.setHex(isSelected ? 0x1a6274 : floor.managed ? 0x123f50 : 0x102534)
              mesh.material.emissive.setHex(isSelected ? 0x0a7480 : floor.managed ? 0x063542 : 0x01080d)
              mesh.material.emissiveIntensity = isSelected ? 1.3 : floor.managed ? 0.65 : 0.15
            })
            visual.glows.forEach(glow => { glow.material.opacity = isSelected ? 0.94 : floor.managed ? 0.42 + Math.sin(elapsed * 1.1 + floor.ordinal) * 0.06 : 0.055 })
          })

          const smooth = (speed: number) => reduceMotion ? 1 : 1 - Math.exp(-speed * delta)
          details.forEach(detail => {
            const target = detail.leaving ? new THREE.Vector3(15.5, 7.2, -1.8) : new THREE.Vector3(8.7, 8.2, -0.4)
            detail.group.position.lerp(target, smooth(detail.leaving ? 5.5 : 4.2))
            const scale = detail.leaving ? 0.92 : 1
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

  if (failed) return <div className="flex h-full items-center justify-center px-8 text-center"><div><p className="text-sm font-medium text-zinc-300">3D rendering is unavailable</p><p className="mt-1 text-xs text-zinc-600">Use the endpoint and equipment lists alongside the map.</p></div></div>
  return <div ref={hostRef} className="h-full w-full" aria-label="Interactive 31-floor 3D Network Map" />
}
