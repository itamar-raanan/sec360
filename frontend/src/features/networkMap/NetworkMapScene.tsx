import { useEffect, useRef, useState } from 'react'

import type { MapAttachment, MapEquipment, MapFloor } from './types'

interface Props {
  floors: MapFloor[]
  equipment: MapEquipment[]
  attachments: MapAttachment[]
  selectedFloorId: string | null
  selectedEquipmentId: string | null
  selectedAttachmentId: string | null
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

export default function NetworkMapScene(props: Props) {
  const hostRef = useRef<HTMLDivElement>(null)
  const callbacks = useRef({ equipment: props.onSelectEquipment, attachment: props.onSelectAttachment })
  const [failed, setFailed] = useState(!webglAvailable())

  callbacks.current = { equipment: props.onSelectEquipment, attachment: props.onSelectAttachment }

  useEffect(() => {
    const host = hostRef.current
    if (!host || failed) return
    let disposed = false
    let frame = 0
    let observer: ResizeObserver | null = null
    let cleanup = () => undefined

    const start = async () => {
      try {
        // Build public asset URLs at runtime so Vite leaves the vendored,
        // browser-native ES modules untouched in development and production.
        const vendorUrl = (parts: string[]) => `${window.location.origin}/${parts.join('/')}`
        const THREE: any = await import(/* @vite-ignore */ vendorUrl(['vendor', 'three', 'three.module.js']))
        const { OrbitControls }: any = await import(/* @vite-ignore */ vendorUrl(['vendor', 'three', 'addons', 'controls', 'OrbitControls.js']))
        if (disposed) return

        const scene = new THREE.Scene()
        scene.background = new THREE.Color(0x070b12)
        scene.fog = new THREE.FogExp2(0x070b12, 0.018)
        const camera = new THREE.OrthographicCamera(-24, 24, 18, -18, 0.1, 300)
        const overviewPosition = new THREE.Vector3(42, 34, 48)
        const floorPosition = new THREE.Vector3(46, 36, 50)
        camera.position.copy(props.selectedFloorId ? floorPosition : overviewPosition)
        const initialLook = new THREE.Vector3(props.selectedFloorId ? 2 : 0, props.selectedFloorId ? 3 : 4, 0)
        camera.lookAt(initialLook)

        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' })
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
        renderer.outputColorSpace = THREE.SRGBColorSpace
        renderer.toneMapping = THREE.ACESFilmicToneMapping
        renderer.toneMappingExposure = 1.3
        host.appendChild(renderer.domElement)

        const controls = new OrbitControls(camera, renderer.domElement)
        controls.enableDamping = true
        controls.dampingFactor = 0.06
        controls.minDistance = 15
        controls.maxDistance = 120
        controls.maxPolarAngle = Math.PI * 0.49
        controls.target.copy(initialLook)
        controls.update()

        scene.add(new THREE.HemisphereLight(0xc7e3ff, 0x111827, 3.3))
        const key = new THREE.DirectionalLight(0xffffff, 3.2)
        key.position.set(18, 30, 12)
        scene.add(key)
        const fill = new THREE.PointLight(0x10b981, 28, 60)
        fill.position.set(-14, 12, -4)
        scene.add(fill)

        const floorMaterial = new THREE.MeshStandardMaterial({ color: 0x16202b, roughness: 0.72, metalness: 0.18 })
        const selectedFloorMaterial = new THREE.MeshStandardMaterial({ color: 0x354b61, roughness: 0.66, metalness: 0.13 })
        const edgeMaterial = new THREE.LineBasicMaterial({ color: 0x3d5973, transparent: true, opacity: 0.72 })
        const wallMaterial = new THREE.MeshStandardMaterial({ color: 0x7890a8, transparent: true, opacity: 0.68, roughness: 0.72 })
        const groups: any[] = []
        const interactive: any[] = []

        const addBox = (parent: any, size: number[], position: number[], material: any) => {
          const mesh = new THREE.Mesh(new THREE.BoxGeometry(...size), material)
          mesh.position.set(...position)
          parent.add(mesh)
          return mesh
        }

        const addFloorShell = (parent: any, expanded: boolean) => {
          const slab = addBox(parent, [22, expanded ? 0.35 : 0.55, 13], [0, 0, 0], expanded ? selectedFloorMaterial : floorMaterial)
          const edges = new THREE.LineSegments(new THREE.EdgesGeometry(slab.geometry), edgeMaterial)
          edges.position.copy(slab.position)
          parent.add(edges)
          if (!expanded) {
            for (const x of [-10.4, 10.4]) addBox(parent, [0.18, 1.25, 13], [x, 0.72, 0], wallMaterial)
            for (const z of [-6.1, 6.1]) addBox(parent, [21, 1.25, 0.18], [0, 0.72, z], wallMaterial)
            return
          }
          // Neutral geometry derived from the supplied plan: perimeter,
          // north/south room bands, central service cores, and open east wing.
          for (const x of [-10.6, 10.6]) addBox(parent, [0.18, 1.05, 12.8], [x, 0.7, 0], wallMaterial)
          for (const z of [-6.3, 6.3]) addBox(parent, [21.4, 1.05, 0.18], [0, 0.7, z], wallMaterial)
          addBox(parent, [15.2, 0.9, 0.16], [-2.5, 0.66, 3.5], wallMaterial)
          addBox(parent, [15.2, 0.9, 0.16], [-2.5, 0.66, -3.7], wallMaterial)
          for (const x of [-8.2, -5.8, -3.3, -0.8, 1.7]) {
            addBox(parent, [0.13, 0.9, 2.7], [x, 0.66, 4.9], wallMaterial)
            addBox(parent, [0.13, 0.9, 2.4], [x, 0.66, -4.9], wallMaterial)
          }
          addBox(parent, [3.1, 1.65, 2.4], [-1.8, 1.0, -0.2], wallMaterial)
          addBox(parent, [2.6, 1.65, 2.6], [2.4, 1.0, 0.3], wallMaterial)
          addBox(parent, [0.14, 0.9, 5.4], [-8.4, 0.66, 0], wallMaterial)
        }

        props.floors.forEach((floor, index) => {
          const group = new THREE.Group()
          group.userData.floorId = floor.id
          const isExpanded = props.selectedFloorId === floor.id
          addFloorShell(group, isExpanded)
          if (props.selectedFloorId) {
            if (isExpanded) group.position.set(2, 18.5, 5)
            else group.position.set(-17, 8 + index * 1.05, 5)
          } else {
            group.position.set(-5, 8 + index * 1.05, 5)
          }
          scene.add(group)
          groups.push(group)
        })

        const selectedGroup = groups.find(group => group.userData.floorId === props.selectedFloorId)
        if (selectedGroup) {
          const floorEquipment = props.equipment.filter(item => item.floor_id === props.selectedFloorId)
          for (const item of floorEquipment) {
            const selected = item.id === props.selectedEquipmentId
            const material = new THREE.MeshStandardMaterial({
              color: item.kind === 'ap' ? 0xdce9f6 : 0x17212d,
              emissive: selected ? 0x10b981 : item.kind === 'ap' ? 0x102d32 : 0x08131a,
              emissiveIntensity: selected ? 1.4 : 0.35,
              roughness: 0.34,
              metalness: 0.35,
            })
            let mesh: any
            if (item.kind === 'ap') {
              mesh = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.58, 0.18, 28), material)
            } else {
              mesh = new THREE.Mesh(new THREE.BoxGeometry(1.15, 0.35, 0.6), material)
            }
            mesh.position.set(item.position.x, 0.55, item.position.z)
            mesh.userData = { type: 'equipment', id: item.id }
            selectedGroup.add(mesh)
            interactive.push(mesh)

            const clients = props.attachments.filter(row => row.equipment_id === item.id).slice(0, 28)
            clients.forEach((row, clientIndex) => {
              const angle = (clientIndex / Math.max(clients.length, 1)) * Math.PI * 2
              const radius = 1.4 + (clientIndex % 4) * 0.42
              const endpointMaterial = new THREE.MeshStandardMaterial({
                color: row.match_state === 'matched' ? 0x36d399 : row.match_state === 'ambiguous' ? 0xf59e0b : 0x64748b,
                emissive: row.id === props.selectedAttachmentId ? 0x10b981 : 0x000000,
                emissiveIntensity: 1.5,
              })
              const endpoint = new THREE.Mesh(new THREE.BoxGeometry(0.3, 0.22, 0.22), endpointMaterial)
              endpoint.position.set(item.position.x + Math.cos(angle) * radius, 0.43, item.position.z + Math.sin(angle) * radius)
              endpoint.userData = { type: 'attachment', id: row.id }
              selectedGroup.add(endpoint)
              interactive.push(endpoint)
              const points = [new THREE.Vector3(item.position.x, 0.45, item.position.z), endpoint.position.clone()]
              const lineGeometry = new THREE.BufferGeometry().setFromPoints(points)
              const lineMaterial = row.attachment_type === 'wireless'
                ? new THREE.LineDashedMaterial({ color: 0x22d3ee, dashSize: 0.17, gapSize: 0.12, transparent: true, opacity: 0.72 })
                : new THREE.LineBasicMaterial({ color: 0x2dd4bf, transparent: true, opacity: 0.74 })
              const line = new THREE.Line(lineGeometry, lineMaterial)
              if (row.attachment_type === 'wireless') line.computeLineDistances()
              selectedGroup.add(line)
            })
          }
        }

        const raycaster = new THREE.Raycaster()
        const pointer = new THREE.Vector2()
        const onPointer = (event: PointerEvent) => {
          const rect = renderer.domElement.getBoundingClientRect()
          pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1
          pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1
          raycaster.setFromCamera(pointer, camera)
          const hit = raycaster.intersectObjects(interactive, false)[0]?.object
          if (hit?.userData.type === 'equipment') callbacks.current.equipment(hit.userData.id)
          if (hit?.userData.type === 'attachment') callbacks.current.attachment(hit.userData.id)
        }
        renderer.domElement.addEventListener('pointerup', onPointer)

        const targetCamera = props.selectedFloorId ? floorPosition : overviewPosition
        const targetLook = new THREE.Vector3(props.selectedFloorId ? 2 : 0, props.selectedFloorId ? 3 : 4, 0)
        const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
        const resize = () => {
          const width = host.clientWidth
          const height = host.clientHeight
          renderer.setSize(width, height, false)
          const aspect = width / Math.max(height, 1)
          const vertical = props.selectedFloorId ? 48 : 42
          camera.left = -(vertical * aspect) / 2
          camera.right = (vertical * aspect) / 2
          camera.top = vertical / 2
          camera.bottom = -vertical / 2
          camera.updateProjectionMatrix()
        }
        observer = new ResizeObserver(resize)
        observer.observe(host)
        resize()
        const animate = () => {
          frame = requestAnimationFrame(animate)
          if (!reduceMotion) {
            camera.position.lerp(targetCamera, 0.035)
            controls.target.lerp(targetLook, 0.045)
          }
          controls.update()
          renderer.render(scene, camera)
        }
        animate()

        cleanup = () => {
          cancelAnimationFrame(frame)
          renderer.domElement.removeEventListener('pointerup', onPointer)
          controls.dispose()
          scene.traverse((object: any) => {
            object.geometry?.dispose?.()
            if (Array.isArray(object.material)) object.material.forEach((material: any) => material.dispose?.())
            else object.material?.dispose?.()
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
