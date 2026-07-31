
export const SPHERE_R = 2.2
const PLANE_W = 2 * Math.PI * SPHERE_R
const PLANE_H = Math.PI * SPHERE_R

export function toSphere(lon, lat, r = SPHERE_R) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)
  return [
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta),
  ]
}

export function toFlat(lon, lat) {
  return [
    (lon / 180) * (PLANE_W / 2),
    (lat / 90) * (PLANE_H / 2),
    0,
  ]
}

export function easeInOutCubic(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2
}

export function buildBuffers(items, getLonLat) {
  const n = items.length
  const flat = new Float32Array(n * 3)
  const sphere = new Float32Array(n * 3)
  for (let i = 0; i < n; i++) {
    const [lon, lat] = getLonLat(items[i])
    const f = toFlat(lon, lat)
    const s = toSphere(lon, lat)
    flat.set(f, i * 3)
    sphere.set(s, i * 3)
  }
  return { flat, sphere }
}
