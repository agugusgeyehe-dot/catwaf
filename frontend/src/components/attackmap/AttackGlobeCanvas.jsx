import { useRef, useMemo, useEffect } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'
import { toSphere, toFlat, easeInOutCubic, SPHERE_R } from './geo3d.js'

// Attack dots are small glowing points in the red family — never large
// geometry, never dark-on-dark. Severity shifts the hue slightly, not the
// importance: everything flashes.
const SEVERITY_COLOR = {
  emergency: '#ff3b3b', alert: '#ff3b3b', critical: '#ff4d4d',
  error: '#ff7043', warning: '#ffa62b',
  notice: '#ff8fa3', info: '#ff8fa3', debug: '#ff8fa3',
}
function colorFor(sev) { return SEVERITY_COLOR[sev] || '#ff6b6b' }

function makeDotTexture() {
  const size = 64
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = size
  const ctx = canvas.getContext('2d')
  const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2)
  g.addColorStop(0, 'rgba(255,255,255,1)')
  g.addColorStop(0.6, 'rgba(255,255,255,0.55)')
  g.addColorStop(1, 'rgba(255,255,255,0)')
  ctx.fillStyle = g
  ctx.fillRect(0, 0, size, size)
  const tex = new THREE.CanvasTexture(canvas)
  return tex
}

function ProgressDriver({ progressRef, target }) {
  useFrame((_, delta) => {
    const p = progressRef.current
    p.value += (target - p.value) * Math.min(delta * 2.6, 1)
    if (Math.abs(target - p.value) < 0.0005) p.value = target
  })
  return null
}

function LandPoints({ landDots, progressRef, motionOff, dotTexture }) {
  const ref = useRef()
  const { flatArr, sphereArr, count } = useMemo(() => {
    const count = landDots.length
    const flatArr = new Float32Array(count * 3)
    const sphereArr = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      const [lon, lat] = landDots[i]
      flatArr.set(toFlat(lon, lat), i * 3)
      sphereArr.set(toSphere(lon, lat), i * 3)
    }
    return { flatArr, sphereArr, count }
  }, [landDots])

  const posAttr = useRef(new Float32Array(count * 3))

  useFrame(() => {
    if (!ref.current) return
    const t = easeInOutCubic(progressRef.current.value)
    const arr = posAttr.current
    for (let i = 0; i < count * 3; i++) arr[i] = flatArr[i] + (sphereArr[i] - flatArr[i]) * t
    ref.current.geometry.attributes.position.needsUpdate = true
  })

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[posAttr.current, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.028}
        map={dotTexture}
        transparent
        opacity={0.75}
        color="#8c96af"
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  )
}

// Attack markers: ONE Points cloud of small soft sprites. Each dot pulses
// its own red — brightness oscillates per-point with a random phase, so an
// active region shimmers instead of one blob throbbing. Size grows only
// slightly with request count and is hard-capped: no more giant spheres.
function AttackMarkers({ points, progressRef, selected, onSelect, onHover, motionOff, dotTexture, markerCap = 300 }) {
  const ref = useRef()
  const { camera, gl } = useThree()
  const capped = useMemo(() => points.slice(0, markerCap), [points, markerCap])
  const count = capped.length

  const { positions, colors, phases } = useMemo(() => {
    const positions = new Float32Array(count * 3)
    const colors = new Float32Array(count * 3)
    const phases = new Float32Array(count)
    const tmp = new THREE.Color()
    capped.forEach((p, i) => {
      positions.set(toSphere(p.lon, p.lat, SPHERE_R * 1.012), i * 3)
      tmp.set(colorFor(p.max_severity))
      colors[i * 3] = tmp.r; colors[i * 3 + 1] = tmp.g; colors[i * 3 + 2] = tmp.b
      phases[i] = Math.random() * Math.PI * 2
    })
    return { positions, colors, phases }
  }, [capped])

  const flatPos = useMemo(() => capped.map(p => toFlat(p.lon, p.lat)), [capped])
  const spherePos = useMemo(() => capped.map(p => toSphere(p.lon, p.lat, SPHERE_R * 1.012)), [capped])

  // Per-frame: position morph (2D↔3D) + red flash. Flash is applied to the
  // color attribute so each dot can beat on its own clock.
  const flashT = useRef(0)
  const baseColors = useMemo(() => colors.slice(), [colors])
  useFrame((_, delta) => {
    if (!ref.current) return
    const t = easeInOutCubic(progressRef.current.value)
    if (!motionOff) flashT.current += delta
    const time = flashT.current

    const posAttr = ref.current.geometry.attributes.position
    const colAttr = ref.current.geometry.attributes.color
    const selKey = selected ? `${selected.lat},${selected.lon}` : null

    for (let i = 0; i < count; i++) {
      const f = flatPos[i], s = spherePos[i]
      posAttr.setXYZ(i,
        f[0] + (s[0] - f[0]) * t,
        f[1] + (s[1] - f[1]) * t,
        f[2] + (s[2] - f[2]) * t)

      const isSel = selKey === `${capped[i].lat},${capped[i].lon}`
      let boost = 1
      if (!motionOff) {
        // Staggered heartbeat: fast enough to read as "live", slow enough to
        // stay calm. Phase offsets de-sync neighbouring dots.
        const wave = (Math.sin(time * 4.2 + phases[i]) + 1) / 2
        boost = 0.42 + 0.78 * wave * wave
      }
      if (isSel) boost = 1.6
      colAttr.setXYZ(i,
        Math.min(baseColors[i * 3] * boost, 1),
        Math.min(baseColors[i * 3 + 1] * boost, 1),
        Math.min(baseColors[i * 3 + 2] * boost, 1))
    }
    posAttr.needsUpdate = true
    colAttr.needsUpdate = true
  })

  return (
    <points
      ref={ref}
      onPointerMove={e => {
        e.stopPropagation()
        const p = capped[e.index]
        if (p && onHover) {
          onHover(p, {
            x: e.nativeEvent.clientX,
            y: e.nativeEvent.clientY,
          })
        }
      }}
      onPointerOut={() => { onHover && onHover(null) }}
      onClick={e => {
        e.stopPropagation()
        const p = capped[e.index]
        if (p && onSelect) onSelect(p)
      }}
    >
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
        <bufferAttribute attach="attributes-color" args={[colors, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.05}
        map={dotTexture}
        vertexColors
        transparent
        opacity={0.95}
        sizeAttenuation
        depthWrite={false}
        toneMapped={false}
      />
    </points>
  )
}

function Atmosphere({ progressRef }) {
  const ref = useRef()
  useFrame(() => {
    if (ref.current) ref.current.material.opacity = 0.12 * easeInOutCubic(progressRef.current.value)
  })
  return (
    <mesh ref={ref} scale={1.06}>
      <sphereGeometry args={[SPHERE_R, 32, 32]} />
      <meshBasicMaterial color="#6aa3ff" transparent opacity={0} side={THREE.BackSide} depthWrite={false} />
    </mesh>
  )
}

function Stars({ progressRef }) {
  const ref = useRef()
  const positions = useMemo(() => {
    const n = 600
    const arr = new Float32Array(n * 3)
    for (let i = 0; i < n; i++) {
      const r = 30 + Math.random() * 20
      const theta = Math.random() * Math.PI * 2
      const phi = Math.acos(2 * Math.random() - 1)
      arr[i * 3] = r * Math.sin(phi) * Math.cos(theta)
      arr[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta)
      arr[i * 3 + 2] = r * Math.cos(phi)
    }
    return arr
  }, [])
  useFrame(() => {
    if (ref.current) ref.current.material.opacity = 0.5 * easeInOutCubic(progressRef.current.value)
  })
  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.06} color="#ffffff" transparent opacity={0} sizeAttenuation depthWrite={false} />
    </points>
  )
}

const CAM_2D = { pos: [0, 0, 12.5], target: [0, 0, 0] }
const CAM_3D = { pos: [4.6, 2.4, 5.4], target: [0, 0, 0] }

function CameraRig({ progressRef, controlsRef }) {
  const { camera } = useThree()
  const settled = useRef(false)
  useFrame(() => {
    const p = progressRef.current.value
    const t = easeInOutCubic(p)
    const active = p > 0.001 && p < 0.999
    if (active || !settled.current) {
      const x = CAM_2D.pos[0] + (CAM_3D.pos[0] - CAM_2D.pos[0]) * t
      const y = CAM_2D.pos[1] + (CAM_3D.pos[1] - CAM_2D.pos[1]) * t
      const z = CAM_2D.pos[2] + (CAM_3D.pos[2] - CAM_2D.pos[2]) * t
      camera.position.set(x, y, z)
      camera.lookAt(0, 0, 0)
      if (controlsRef.current) controlsRef.current.target.set(0, 0, 0)
      settled.current = !active
    }
  })
  return null
}

export default function AttackGlobeCanvas({
  landDots, points, selected, onSelect, onHover, mode, autoRotate, motionOff, resetSignal, markerCap = 300,
}) {
  const progressRef = useRef({ value: mode === '3d' ? 1 : 0 })
  const controlsRef = useRef()
  const dotTexture = useMemo(() => makeDotTexture(), [])

  useEffect(() => {
    if (!controlsRef.current) return
    controlsRef.current.reset()
  }, [resetSignal])

  return (
    <Canvas
      camera={{ position: CAM_2D.pos, fov: 42 }}
      gl={{ antialias: true, alpha: true }}
      dpr={[1, 1.75]}
      raycaster={{ params: { Points: { threshold: 0.09 } } }}
      style={{ touchAction: 'none' }}
    >
      <ambientLight intensity={1.1} />
      <ProgressDriver progressRef={progressRef} target={mode === '3d' ? 1 : 0} />
      <CameraRig progressRef={progressRef} controlsRef={controlsRef} />
      <Stars progressRef={progressRef} />
      <Atmosphere progressRef={progressRef} />
      <LandPoints landDots={landDots} progressRef={progressRef} motionOff={motionOff} dotTexture={dotTexture} />
      <AttackMarkers
        points={points}
        progressRef={progressRef}
        selected={selected}
        onSelect={onSelect}
        onHover={onHover}
        motionOff={motionOff}
        dotTexture={dotTexture}
        markerCap={markerCap}
      />
      <OrbitControls
        ref={controlsRef}
        enablePan={false}
        enableDamping
        dampingFactor={0.08}
        rotateSpeed={0.55}
        minDistance={3.2}
        maxDistance={16}
        autoRotate={autoRotate && mode === '3d' && !motionOff}
        autoRotateSpeed={0.6}
      />
    </Canvas>
  )
}
