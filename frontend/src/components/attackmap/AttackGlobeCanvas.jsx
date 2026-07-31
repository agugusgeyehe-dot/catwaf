import React, { useRef, useMemo, useEffect } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'
import { toSphere, toFlat, easeInOutCubic, SPHERE_R } from './geo3d.js'

const SEVERITY_COLOR = {
  emergency: '#f25c5c', alert: '#f25c5c', critical: '#f25c5c',
  error: '#f59e0b', warning: '#eab308',
  notice: '#7c8db0', info: '#7c8db0', debug: '#7c8db0',
}
function colorFor(sev) { return SEVERITY_COLOR[sev] || '#5c6577' }

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

function AttackMarkers({ points, progressRef, selected, onSelect, motionOff, markerCap = 300 }) {
  const ref = useRef()
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const capped = useMemo(() => points.slice(0, markerCap), [points, markerCap])
  const geo = useMemo(() => new THREE.SphereGeometry(1, 12, 12), [])
  const colorArr = useMemo(() => {
    const arr = new Float32Array(capped.length * 3)
    capped.forEach((p, i) => {
      const c = new THREE.Color(colorFor(p.max_severity))
      arr[i * 3] = c.r; arr[i * 3 + 1] = c.g; arr[i * 3 + 2] = c.b
    })
    return arr
  }, [capped])

  const flatPos = useMemo(() => capped.map(p => toFlat(p.lon, p.lat)), [capped])
  const spherePos = useMemo(() => capped.map(p => toSphere(p.lon, p.lat, SPHERE_R * 1.01)), [capped])

  useEffect(() => {
    if (!ref.current) return
    ref.current.instanceColor = new THREE.InstancedBufferAttribute(colorArr, 3)
    ref.current.instanceColor.needsUpdate = true
  }, [colorArr])

  const pulseT = useRef(0)
  useFrame((_, delta) => {
    if (!ref.current) return
    const t = easeInOutCubic(progressRef.current.value)
    if (!motionOff) pulseT.current += delta
    const pulse = motionOff ? 0 : (Math.sin(pulseT.current * 2) + 1) / 2
    capped.forEach((p, i) => {
      const f = flatPos[i], s = spherePos[i]
      const x = f[0] + (s[0] - f[0]) * t
      const y = f[1] + (s[1] - f[1]) * t
      const z = f[2] + (s[2] - f[2]) * t
      dummy.position.set(x, y, z)
      const isSel = selected && selected.lat === p.lat && selected.lon === p.lon
      const base = 0.045 + Math.min(Math.log2(p.count + 1) * 0.028, 0.22)
      const scale = base * (1 + pulse * 0.18) * (isSel ? 1.6 : 1)
      dummy.scale.setScalar(scale)
      dummy.updateMatrix()
      ref.current.setMatrixAt(i, dummy.matrix)
    })
    ref.current.instanceMatrix.needsUpdate = true
  })

  return (
    <instancedMesh
      ref={ref}
      args={[geo, undefined, capped.length]}
      onClick={e => {
        e.stopPropagation()
        const p = capped[e.instanceId]
        if (p) onSelect(p)
      }}
    >
      <meshBasicMaterial vertexColors toneMapped={false} />
    </instancedMesh>
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
  landDots, points, selected, onSelect, mode, autoRotate, motionOff, resetSignal, markerCap = 300,
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
      style={{ touchAction: 'none' }}
    >
      <ambientLight intensity={1.1} />
      <ProgressDriver progressRef={progressRef} target={mode === '3d' ? 1 : 0} />
      <CameraRig progressRef={progressRef} controlsRef={controlsRef} />
      <Stars progressRef={progressRef} />
      <Atmosphere progressRef={progressRef} />
      <LandPoints landDots={landDots} progressRef={progressRef} motionOff={motionOff} dotTexture={dotTexture} />
      <AttackMarkers points={points} progressRef={progressRef} selected={selected} onSelect={onSelect} motionOff={motionOff} markerCap={markerCap} />
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
