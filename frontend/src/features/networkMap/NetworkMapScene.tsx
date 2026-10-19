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
  const callbacks = useRef({
    floor: props.onSelectFloor,
    equipment: props.onSelectEquipment,
    attachment: props.onSelectAttachment,
  })
  const [failed, setFailed] = useState(!webglAvailable())

  callbacks.current = {
    floor: props.onSelectFloor,
    equipment: props.onSelectEquipment,
    attachment: props.onSelectAttachment,
  }

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
        scene.fog = new THREE.FogExp2(0x030913, 0.012)

        const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 320)
        const overviewPosition = new THREE.Vector3(38, 30, 68)
        const floorPosition = new THREE.Vector3(34, 24, 47)
        const overviewLook = new THREE.Vector3(-8.5, 10.2, 1.5)
        const floorLook = new THREE.Vector3(1.2, 8.8, 0.7)
        camera.position.copy(props.selectedFloorId && !reduceMotion ? overviewPosition : props.selectedFloorId ? floorPosition : overviewPosition)
        camera.lookAt(props.selectedFloorId ? floorLook : overviewLook)

        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' })
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
        renderer.outputColorSpace = THREE.SRGBColorSpace
        renderer.toneMapping = THREE.ACESFilmicToneMapping
        renderer.toneMappingExposure = 1.32
        renderer.shadowMap.enabled = true
        renderer.shadowMap.type = THREE.PCFSoftShadowMap
        renderer.domElement.style.touchAction = 'none'
        host.appendChild(renderer.domElement)

        const controls = new OrbitControls(camera, renderer.domElement)
        controls.enableDamping = true
        controls.dampingFactor = 0.075
        controls.enablePan = true
        controls.minDistance = 20
        controls.maxDistance = 95
        controls.minPolarAngle = Math.PI * 0.08
        controls.maxPolarAngle = Math.PI * 0.49
        controls.target.copy(props.selectedFloorId ? floorLook : overviewLook)
        controls.update()

        scene.add(new THREE.HemisphereLight(0xa8dcff, 0x03050a, 3.2))
        const key = new THREE.DirectionalLight(0xeaf6ff, 5.8)
        key.position.set(22, 34, 18)
        key.castShadow = true
        key.shadow.mapSize.set(2048, 2048)
        key.shadow.camera.near = 1
        key.shadow.camera.far = 90
        key.shadow.camera.left = -35
        key.shadow.camera.right = 35
        key.shadow.camera.top = 35
        key.shadow.camera.bottom = -35
        scene.add(key)
        const cyanLight = new THREE.PointLight(0x14dbe5, 80, 60, 2)
        cyanLight.position.set(-10, 12, 7)
        scene.add(cyanLight)
        const blueLight = new THREE.PointLight(0x2c72ff, 65, 75, 2)
        blueLight.position.set(16, 16, -15)
        scene.add(blueLight)

        const world = new THREE.Group()
        scene.add(world)
        const interactive: any[] = []
        const animatedPulses: Array<{ mesh: any; curve: any; phase: number; speed: number }> = []
        const animatedRings: Array<{ mesh: any; phase: number }> = []
        const animatedBands: Array<{ material: any; phase: number }> = []
        const floorGroups: Array<{ group: any; start: any; target: any; floorId: string }> = []

        const addBox = (parent: any, size: number[], position: number[], material: any) => {
          const mesh = new THREE.Mesh(new THREE.BoxGeometry(...size), material)
          mesh.position.set(...position)
          mesh.castShadow = true
          mesh.receiveShadow = true
          parent.add(mesh)
          return mesh
        }

        const addEdges = (parent: any, mesh: any, color = 0x5ea3c7, opacity = 0.46) => {
          const edges = new THREE.LineSegments(
            new THREE.EdgesGeometry(mesh.geometry),
            new THREE.LineBasicMaterial({ color, transparent: true, opacity }),
          )
          edges.position.copy(mesh.position)
          edges.rotation.copy(mesh.rotation)
          parent.add(edges)
          return edges
        }

        const makeLabel = (text: string, accent = false) => {
          const canvas = document.createElement('canvas')
          const context = canvas.getContext('2d')!
          const ratio = 2
          canvas.width = 256 * ratio
          canvas.height = 62 * ratio
          context.scale(ratio, ratio)
          context.font = '600 17px ui-sans-serif, system-ui, sans-serif'
          context.textAlign = 'center'
          context.textBaseline = 'middle'
          context.fillStyle = 'rgba(4, 12, 22, 0.90)'
          context.strokeStyle = accent ? 'rgba(34, 211, 238, 0.78)' : 'rgba(120, 166, 190, 0.42)'
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

        // A restrained procedural city gives the tower scale and depth without competing with live data.
        const random = seededRandom(360)
        const cityMaterial = new THREE.MeshStandardMaterial({ color: 0x07111d, roughness: 0.94, metalness: 0.05 })
        const cityGlow = new THREE.MeshBasicMaterial({ color: 0x0d3a4b, transparent: true, opacity: 0.22 })
        for (let i = 0; i < 74; i += 1) {
          const angle = random() * Math.PI * 2
          const radius = 30 + random() * 58
          const width = 2 + random() * 6
          const depth = 2 + random() * 6
          const height = 1.2 + Math.pow(random(), 2) * 14
          const x = Math.cos(angle) * radius
          const z = Math.sin(angle) * radius
          const block = addBox(world, [width, height, depth], [x, height / 2 - 1.2, z], cityMaterial)
          block.castShadow = false
          if (i % 3 === 0) addBox(world, [width * 0.72, 0.05, 0.04], [x, height * 0.58, z + depth / 2 + 0.025], cityGlow).castShadow = false
        }

        const ground = new THREE.Mesh(
          new THREE.CircleGeometry(105, 96),
          new THREE.MeshStandardMaterial({ color: 0x020711, roughness: 0.94, metalness: 0.05 }),
        )
        ground.rotation.x = -Math.PI / 2
        ground.position.y = -1.22
        ground.receiveShadow = true
        world.add(ground)
        const grid = new THREE.GridHelper(150, 60, 0x0e4254, 0x09202d)
        grid.position.y = -1.18
        grid.material.transparent = true
        grid.material.opacity = 0.2
        world.add(grid)

        const glassMaterial = new THREE.MeshPhysicalMaterial({
          color: 0x173b54,
          metalness: 0.22,
          roughness: 0.16,
          transmission: 0.18,
          transparent: true,
          opacity: 0.8,
          clearcoat: 0.72,
          clearcoatRoughness: 0.2,
          side: THREE.DoubleSide,
        })
        const darkGlassMaterial = new THREE.MeshPhysicalMaterial({
          color: 0x061725,
          metalness: 0.36,
          roughness: 0.2,
          transparent: true,
          opacity: 0.88,
          clearcoat: 0.8,
        })
        const structuralMaterial = new THREE.MeshStandardMaterial({ color: 0xa9bcc7, metalness: 0.68, roughness: 0.27 })
        const slabMaterial = new THREE.MeshStandardMaterial({ color: 0x182a39, metalness: 0.28, roughness: 0.56 })
        const selectedSlabMaterial = new THREE.MeshStandardMaterial({ color: 0x607785, metalness: 0.18, roughness: 0.42 })
        const wallMaterial = new THREE.MeshPhysicalMaterial({ color: 0xb9d3dc, transparent: true, opacity: 0.6, roughness: 0.52, side: THREE.DoubleSide })
        const accentMaterial = new THREE.MeshBasicMaterial({ color: 0x16e4ef, transparent: true, opacity: 0.8 })

        const tower = new THREE.Group()
        tower.position.set(-8.5, 0, 1.5)
        world.add(tower)

        addBox(tower, [16.5, 1.15, 11.5], [0, -0.58, 0], darkGlassMaterial)
        addBox(tower, [14.8, 0.24, 9.9], [0, 0.12, 0], structuralMaterial)

        const addFloorPlan = (parent: any) => {
          // Floor-25 proportions: perimeter offices, central services, and an open collaboration wing.
          const perimeter = [
            [[0.16, 1.05, 12.5], [-10.5, 0.72, 0]], [[0.16, 1.05, 12.5], [10.5, 0.72, 0]],
            [[21.1, 1.05, 0.16], [0, 0.72, -6.15]], [[21.1, 1.05, 0.16], [0, 0.72, 6.15]],
          ] as const
          perimeter.forEach(([size, position]) => addBox(parent, [...size], [...position], wallMaterial))
          addBox(parent, [14.5, 0.82, 0.13], [-2.4, 0.6, 3.55], wallMaterial)
          addBox(parent, [14.5, 0.82, 0.13], [-2.4, 0.6, -3.65], wallMaterial)
          for (const x of [-8.25, -5.9, -3.55, -1.2, 1.15]) {
            addBox(parent, [0.12, 0.82, 2.55], [x, 0.6, 4.83], wallMaterial)
            addBox(parent, [0.12, 0.82, 2.35], [x, 0.6, -4.82], wallMaterial)
          }
          addBox(parent, [3.05, 1.5, 2.35], [-1.7, 0.9, -0.15], darkGlassMaterial)
          addBox(parent, [2.45, 1.5, 2.55], [2.25, 0.9, 0.2], darkGlassMaterial)
          addBox(parent, [0.12, 0.82, 5.25], [-8.35, 0.6, 0], wallMaterial)
          for (const x of [-7.1, -4.6, -2.1, 0.4, 5.6, 8.1]) {
            const desk = addBox(parent, [1.2, 0.08, 0.52], [x, 0.48, x > 3 ? 2.4 : -2.25], structuralMaterial)
            desk.castShadow = false
          }
        }

        props.floors.forEach((floor, index) => {
          const group = new THREE.Group()
          group.userData = { type: 'floor', id: floor.id }
          const floorY = 0.55 + index * 2.42
          const taper = 1 - index * 0.012
          const width = 14.2 * taper
          const depth = 9.25 * taper
          const selected = props.selectedFloorId === floor.id
          const slab = addBox(group, [selected ? 21.2 : width, selected ? 0.34 : 0.26, selected ? 12.5 : depth], [0, 0, 0], selected ? selectedSlabMaterial : slabMaterial)
          slab.userData = { type: 'floor', id: floor.id }
          interactive.push(slab)
          addEdges(group, slab, selected ? 0x5cebf1 : 0x4689a8, selected ? 0.78 : 0.42)

          if (selected) {
            addFloorPlan(group)
            const floorGrid = new THREE.GridHelper(20.8, 22, 0x78b5c7, 0x314b5b)
            floorGrid.scale.z = 0.59
            floorGrid.position.y = 0.2
            floorGrid.material.transparent = true
            floorGrid.material.opacity = 0.22
            group.add(floorGrid)
          } else {
            addBox(group, [width, 2.06, depth], [0, 1.14, 0], glassMaterial)
            addBox(group, [width + 0.12, 0.08, depth + 0.12], [0, 2.2, 0], structuralMaterial)
            addBox(group, [width + 0.12, 0.035, depth + 0.16], [0, 1.12, 0], structuralMaterial).castShadow = false
            for (const x of [-width / 2, width / 2]) addBox(group, [0.08, 2.28, depth + 0.35], [x, 1.12, 0], structuralMaterial)
            for (let x = -width / 2 + 1.25; x < width / 2; x += 1.25) {
              addBox(group, [0.035, 2.02, 0.045], [x, 1.14, depth / 2 + 0.03], structuralMaterial).castShadow = false
              addBox(group, [0.035, 2.02, 0.045], [x, 1.14, -depth / 2 - 0.03], structuralMaterial).castShadow = false
            }
            const bandMaterial = accentMaterial.clone()
            bandMaterial.opacity = selected ? 1 : 0.14
            addBox(group, [width + 0.28, 0.055, depth + 0.28], [0, 0.2, 0], bandMaterial).castShadow = false
            animatedBands.push({ material: bandMaterial, phase: index / Math.max(props.floors.length, 1) })
          }

          const towerPosition = new THREE.Vector3(0, floorY, 0)
          const expandedPosition = new THREE.Vector3(19, 9.5, -0.8)
          const parkedPosition = towerPosition.clone()
          if (props.selectedFloorId && !selected) parkedPosition.x = -0.5
          const start = towerPosition.clone()
          const target = selected ? expandedPosition : parkedPosition
          group.position.copy(reduceMotion ? target : start)
          if (selected) group.rotation.y = -0.08
          tower.add(group)
          floorGroups.push({ group, start, target, floorId: floor.id })
        })

        // Tapered crown and twin illuminated fins reproduce the uploaded tower silhouette.
        const crownY = 0.55 + props.floors.length * 2.42
        addBox(tower, [12.7, 0.7, 8.2], [0, crownY, 0], darkGlassMaterial)
        const crown = new THREE.Mesh(new THREE.ConeGeometry(6.2, 4.8, 4), darkGlassMaterial)
        crown.rotation.y = Math.PI / 4
        crown.scale.z = 0.67
        crown.position.set(0, crownY + 2.5, 0)
        tower.add(crown)
        for (const x of [-6.75, 6.75]) {
          const fin = addBox(tower, [0.13, props.floors.length * 2.42 + 5.2, 0.34], [x, crownY / 2 + 1.4, 0], structuralMaterial)
          fin.rotation.z = x < 0 ? -0.025 : 0.025
        }

        const selectedGroup = floorGroups.find(row => row.floorId === props.selectedFloorId)?.group
        if (selectedGroup) {
          const floorLight = new THREE.PointLight(0xbfefff, 48, 28, 2)
          floorLight.position.set(0, 7, 0)
          selectedGroup.add(floorLight)
          const floorEquipment = props.equipment.filter(item => item.floor_id === props.selectedFloorId)
          for (const item of floorEquipment) {
            const selected = item.id === props.selectedEquipmentId
            const x = THREE.MathUtils.clamp(item.position.x, -9.5, 9.5)
            const z = THREE.MathUtils.clamp(item.position.z, -5.4, 5.4)
            const deviceGroup = new THREE.Group()
            deviceGroup.position.set(x, 0.28, z)
            deviceGroup.userData = { type: 'equipment', id: item.id }
            selectedGroup.add(deviceGroup)

            if (item.kind === 'ap') {
              const bodyMaterial = new THREE.MeshPhysicalMaterial({ color: 0xe5f3f6, roughness: 0.24, metalness: 0.12, clearcoat: 0.9 })
              const body = new THREE.Mesh(new THREE.CylinderGeometry(0.65, 0.73, 0.2, 40), bodyMaterial)
              body.position.y = 0.35
              body.userData = deviceGroup.userData
              body.castShadow = true
              deviceGroup.add(body)
              interactive.push(body)
              const cap = new THREE.Mesh(new THREE.TorusGeometry(0.22, 0.025, 8, 40), accentMaterial)
              cap.rotation.x = Math.PI / 2
              cap.position.y = 0.45
              deviceGroup.add(cap)
              for (let ringIndex = 0; ringIndex < 3; ringIndex += 1) {
                const ring = new THREE.Mesh(
                  new THREE.RingGeometry(0.62, 0.66, 48),
                  new THREE.MeshBasicMaterial({ color: 0x20e8f3, transparent: true, opacity: 0.22, side: THREE.DoubleSide, depthWrite: false }),
                )
                ring.rotation.x = -Math.PI / 2
                ring.position.y = 0.22
                ring.scale.setScalar(1 + ringIndex * 0.42)
                deviceGroup.add(ring)
                animatedRings.push({ mesh: ring, phase: ringIndex / 3 + floorEquipment.indexOf(item) * 0.13 })
              }
            } else {
              const switchBody = addBox(deviceGroup, [1.35, 0.38, 0.72], [0, 0.28, 0], darkGlassMaterial)
              switchBody.userData = deviceGroup.userData
              interactive.push(switchBody)
              for (let port = 0; port < 8; port += 1) {
                const portMaterial = new THREE.MeshBasicMaterial({ color: port % 3 === 0 ? 0x25e6cf : 0x315267 })
                addBox(deviceGroup, [0.1, 0.08, 0.02], [-0.49 + port * 0.14, 0.29, 0.37], portMaterial).castShadow = false
              }
            }

            const label = makeLabel(item.name, selected)
              label.position.set(0, 1.55, 0)
            deviceGroup.add(label)

            const clients = props.attachments.filter(row => row.equipment_id === item.id).slice(0, 32)
            clients.forEach((row, clientIndex) => {
              const angle = (clientIndex / Math.max(clients.length, 1)) * Math.PI * 2 + (clientIndex % 2) * 0.28
              const radius = 1.65 + (clientIndex % 5) * 0.53
              const endpointPosition = new THREE.Vector3(
                THREE.MathUtils.clamp(x + Math.cos(angle) * radius, -9.6, 9.6),
                0.38,
                THREE.MathUtils.clamp(z + Math.sin(angle) * radius, -5.25, 5.25),
              )
              const endpointMaterial = new THREE.MeshStandardMaterial({
                color: row.match_state === 'matched' ? 0x55e6cf : row.match_state === 'ambiguous' ? 0xf3b85b : 0x708393,
                emissive: row.id === props.selectedAttachmentId ? 0x1bd7df : 0x071018,
                emissiveIntensity: row.id === props.selectedAttachmentId ? 2.4 : 0.5,
                metalness: 0.35,
                roughness: 0.35,
              })
              const endpointGroup = new THREE.Group()
              endpointGroup.position.copy(endpointPosition)
              endpointGroup.userData = { type: 'attachment', id: row.id }
              const base = addBox(endpointGroup, [0.58, 0.06, 0.4], [0, 0, 0], endpointMaterial)
              base.userData = endpointGroup.userData
              interactive.push(base)
              const screen = addBox(endpointGroup, [0.56, 0.4, 0.055], [0, 0.24, -0.13], endpointMaterial)
              screen.rotation.x = -0.16
              screen.userData = endpointGroup.userData
              interactive.push(screen)
              selectedGroup.add(endpointGroup)

              const startPoint = new THREE.Vector3(x, 0.57, z)
              const endPoint = endpointPosition.clone().setY(0.48)
              const midpoint = startPoint.clone().lerp(endPoint, 0.5)
              midpoint.y += 0.22 + Math.min(startPoint.distanceTo(endPoint) * 0.04, 0.5)
              const curve = new THREE.QuadraticBezierCurve3(startPoint, midpoint, endPoint)
              const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(24))
              const lineMaterial = row.attachment_type === 'wireless'
                ? new THREE.LineDashedMaterial({ color: 0x20dceb, dashSize: 0.2, gapSize: 0.13, transparent: true, opacity: 0.56 })
                : new THREE.LineBasicMaterial({ color: 0x2ce0bd, transparent: true, opacity: 0.62 })
              const line = new THREE.Line(geometry, lineMaterial)
              if (row.attachment_type === 'wireless') line.computeLineDistances()
              selectedGroup.add(line)
              const pulse = new THREE.Mesh(
                new THREE.SphereGeometry(0.1, 12, 12),
                new THREE.MeshBasicMaterial({ color: row.attachment_type === 'wireless' ? 0x7ff5ff : 0x72ffd8 }),
              )
              selectedGroup.add(pulse)
              animatedPulses.push({ mesh: pulse, curve, phase: clientIndex / Math.max(clients.length, 1), speed: 0.16 + (clientIndex % 4) * 0.025 })
            })
          }
        }

        // The dashed bridge makes the building-to-floor relationship explicit.
        if (props.selectedFloorId) {
          const selectedIndex = props.floors.findIndex(floor => floor.id === props.selectedFloorId)
          const sourceY = 0.55 + selectedIndex * 2.42 + 1.1
          const bridgeCurve = new THREE.QuadraticBezierCurve3(
            new THREE.Vector3(-1.2, sourceY, 1.5),
            new THREE.Vector3(0.5, Math.max(sourceY, 8) + 2.5, 0.5),
            new THREE.Vector3(10, 7.8, 0.7),
          )
          const bridgeGeometry = new THREE.BufferGeometry().setFromPoints(bridgeCurve.getPoints(48))
          const bridge = new THREE.Line(
            bridgeGeometry,
            new THREE.LineDashedMaterial({ color: 0x24dbe7, dashSize: 0.42, gapSize: 0.24, transparent: true, opacity: 0.72 }),
          )
          bridge.computeLineDistances()
          world.add(bridge)
        }

        const raycaster = new THREE.Raycaster()
        const pointer = new THREE.Vector2()
        let downX = 0
        let downY = 0
        let hovered: any = null
        const setPointer = (event: PointerEvent) => {
          const rect = renderer.domElement.getBoundingClientRect()
          pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1
          pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1
          raycaster.setFromCamera(pointer, camera)
        }
        const onPointerDown = (event: PointerEvent) => { downX = event.clientX; downY = event.clientY }
        const onPointerMove = (event: PointerEvent) => {
          setPointer(event)
          const hit = raycaster.intersectObjects(interactive, false)[0]?.object || null
          if (hovered !== hit) {
            if (hovered) hovered.scale.setScalar(1)
            hovered = hit
            if (hovered) hovered.scale.setScalar(1.06)
            renderer.domElement.style.cursor = hovered ? 'pointer' : 'grab'
          }
        }
        const onPointerUp = (event: PointerEvent) => {
          if (Math.hypot(event.clientX - downX, event.clientY - downY) > 7) return
          setPointer(event)
          const hit = raycaster.intersectObjects(interactive, false)[0]?.object
          if (hit?.userData.type === 'floor') callbacks.current.floor(hit.userData.id)
          if (hit?.userData.type === 'equipment') callbacks.current.equipment(hit.userData.id)
          if (hit?.userData.type === 'attachment') callbacks.current.attachment(hit.userData.id)
        }
        renderer.domElement.addEventListener('pointerdown', onPointerDown)
        renderer.domElement.addEventListener('pointermove', onPointerMove)
        renderer.domElement.addEventListener('pointerup', onPointerUp)
        renderer.domElement.addEventListener('pointerleave', () => { renderer.domElement.style.cursor = 'grab' })

        const targetCamera = props.selectedFloorId ? floorPosition : overviewPosition
        const targetLook = props.selectedFloorId ? floorLook : overviewLook
        const resize = () => {
          const width = host.clientWidth
          const height = host.clientHeight
          // Keep the CSS viewport independent from the high-DPI drawing buffer.
          // Without the style update a 2× display renders a 2560px canvas into a
          // 1280px host, cropping the camera framing to its upper-left quadrant.
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
          const elapsed = clock.getElapsedTime()
          if (!reduceMotion) {
            camera.position.lerp(targetCamera, 0.025)
            controls.target.lerp(targetLook, 0.035)
            floorGroups.forEach(({ group, target }) => {
              group.position.lerp(target, 0.055)
              if (group.position.distanceTo(target) < 0.002) group.position.copy(target)
            })
            animatedRings.forEach(({ mesh, phase }) => {
              const cycle = (elapsed * 0.42 + phase) % 1
              const scale = 0.86 + cycle * 1.35
              mesh.scale.setScalar(scale)
              mesh.material.opacity = (1 - cycle) * 0.28
            })
            animatedPulses.forEach(({ mesh, curve, phase, speed }) => {
              mesh.position.copy(curve.getPoint((elapsed * speed + phase) % 1))
            })
            animatedBands.forEach(({ material, phase }) => {
              material.opacity = 0.1 + Math.pow(Math.max(0, Math.sin(elapsed * 1.15 - phase * Math.PI * 2)), 8) * 0.72
            })
            cyanLight.intensity = 72 + Math.sin(elapsed * 0.8) * 8
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
            materials.forEach((material: any) => {
              material.map?.dispose?.()
              material.dispose?.()
            })
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
    return () => {
      disposed = true
      observer?.disconnect()
      cleanup()
    }
  }, [props.floors, props.equipment, props.attachments, props.selectedFloorId, props.selectedEquipmentId, props.selectedAttachmentId, failed])

  if (failed) return <div className="flex h-full items-center justify-center px-8 text-center"><div><p className="text-sm font-medium text-zinc-300">3D rendering is unavailable</p><p className="mt-1 text-xs text-zinc-600">Use the endpoint and equipment lists alongside the map.</p></div></div>
  return <div ref={hostRef} className="h-full w-full" aria-label="Interactive 3D Network Map" />
}
