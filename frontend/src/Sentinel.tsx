import { useId } from 'react';

// RepoSentinel's visual signature: a lattice globe (latitude and longitude
// lines seen from slightly above) around a faceted shield core, with an orbit
// ring. It is decorative (aria-hidden) and drawn once as static SVG; the only
// motion is a radar sweep shown while a scan is really running, and a slow
// orbit drift, both switched off by prefers-reduced-motion (see styles.css).

const R = 150;
const C = 200;
const TILT = 0.32; // radians the viewer looks down by

function latitude(lat: number) {
  const rx = R * Math.cos(lat);
  return { rx, ry: rx * Math.sin(TILT), cy: C - R * Math.sin(lat) * Math.cos(TILT) };
}

const LATS = [-60, -40, -20, 0, 20, 40, 60].map((deg) => latitude((deg * Math.PI) / 180));
const LONS = [0, 30, 60, 90, 120, 150].map((deg) => R * Math.abs(Math.cos((deg * Math.PI) / 180)));

// Lattice nodes on the front half, where latitude and longitude lines meet.
const NODES: { x: number; y: number; r: number }[] = [];
for (const latDeg of [-40, -20, 0, 20, 40]) {
  const lat = (latDeg * Math.PI) / 180;
  for (const lonDeg of [-60, -30, 0, 30, 60]) {
    const lon = (lonDeg * Math.PI) / 180;
    const x = C + R * Math.cos(lat) * Math.sin(lon);
    const z = Math.cos(lat) * Math.cos(lon); // toward the viewer
    const y = C - R * (Math.sin(lat) * Math.cos(TILT) - z * Math.sin(TILT) * 0.35);
    if ((latDeg * 7 + lonDeg) % 3 === 0 || lonDeg === 0) NODES.push({ x, y, r: 1.6 + z * 1.6 });
  }
}

const SHIELD = 'M200 128l52 19v38c0 34-22.5 61-52 72-29.5-11-52-38-52-72v-38z';

export function SentinelGlobe(props: { scanning?: boolean; size?: number; className?: string }) {
  const id = useId().replace(/:/g, '');
  const size = props.size ?? 360;
  return (
    <svg
      className={`sentinel ${props.scanning ? 'is-scanning' : ''} ${props.className ?? ''}`}
      width={size}
      height={size}
      viewBox="0 0 400 400"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <radialGradient id={`${id}-glow`} cx="50%" cy="46%" r="55%">
          <stop offset="0" stopColor="#ff7a2f" stopOpacity="0.34" />
          <stop offset="0.55" stopColor="#c2410c" stopOpacity="0.1" />
          <stop offset="1" stopColor="#000" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`${id}-line`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#ffb98a" stopOpacity="0.95" />
          <stop offset="1" stopColor="#c2410c" stopOpacity="0.35" />
        </linearGradient>
        <linearGradient id={`${id}-shield`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#ffb27a" />
          <stop offset="1" stopColor="#d9561f" />
        </linearGradient>
        <radialGradient id={`${id}-sweep`} cx="50%" cy="50%" r="50%">
          <stop offset="0" stopColor="#ff8a4c" stopOpacity="0" />
          <stop offset="1" stopColor="#ff8a4c" stopOpacity="0.32" />
        </radialGradient>
      </defs>
      <circle cx={C} cy={C} r="196" fill={`url(#${id}-glow)`} />
      <g className="sentinel-lattice" fill="none" stroke={`url(#${id}-line)`} strokeWidth="0.9">
        <circle cx={C} cy={C} r={R} strokeWidth="1.3" />
        {LATS.map((lat) => (
          <ellipse key={lat.cy} cx={C} cy={lat.cy} rx={lat.rx} ry={lat.ry} opacity="0.75" />
        ))}
        {LONS.map((rx, index) => (
          <ellipse key={index} cx={C} cy={C} rx={rx} ry={R} opacity={0.35 + (rx / R) * 0.4} />
        ))}
      </g>
      <g className="sentinel-orbit" fill="none" stroke="#ff9a5c" strokeWidth="1.1">
        <ellipse cx={C} cy={C + 8} rx="188" ry="44" strokeDasharray="2 9" opacity="0.7" transform={`rotate(-14 ${C} ${C})`} />
      </g>
      {props.scanning && (
        <g className="sentinel-sweep">
          <path d={`M${C} ${C} L${C} ${C - R} A${R} ${R} 0 0 1 ${C + R * Math.sin(0.9)} ${C - R * Math.cos(0.9)} Z`} fill={`url(#${id}-sweep)`} />
        </g>
      )}
      <g className="sentinel-nodes" fill="#ffcfa8">
        {NODES.map((node, index) => (
          <circle key={index} cx={node.x} cy={node.y} r={Math.max(1, node.r)} />
        ))}
      </g>
      <g className="sentinel-core">
        <path d={SHIELD} fill="#1a0f0a" fillOpacity="0.72" stroke={`url(#${id}-shield)`} strokeWidth="2.4" />
        <path d="M200 146l36 13v26c0 23.5-15.5 42.5-36 50.5-20.5-8-36-27-36-50.5v-26z" fill="none" stroke="#ff9a5c" strokeOpacity="0.45" strokeWidth="1" />
        <path d="M168 192h64" stroke="#ffd2b0" strokeWidth="2" strokeLinecap="round" className="sentinel-scanline" />
        <circle cx={C} cy="192" r="5" fill="#ffd2b0" />
      </g>
    </svg>
  );
}
