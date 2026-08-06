import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

const AXIS_TICK = { fontSize: 10, fill: 'var(--cat-sub)' }

const tooltipStyles = {
  contentStyle: {
    background: 'var(--cat-card-final, var(--cat-card))',
    border: '1px solid var(--cat-border-final, var(--cat-border))',
    borderRadius: 8,
    fontSize: 11,
    color: 'var(--cat-text)',
    boxShadow: '0 8px 24px -8px rgba(0,0,0,0.45)',
  },
  labelStyle: { color: 'var(--cat-sub)', fontSize: 10, marginBottom: 2 },
  itemStyle: { color: 'var(--cat-text)' },
  cursor: { stroke: 'var(--cat-border)', strokeWidth: 1 },
}

export function TrafficAreaChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
        <defs>
          <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#4f8ef7" stopOpacity={0.2} />
            <stop offset="95%" stopColor="#4f8ef7" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gBlock" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#f25c5c" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#f25c5c" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="hour" tick={AXIS_TICK} interval={3} stroke="var(--cat-border)" />
        <YAxis tick={AXIS_TICK} stroke="var(--cat-border)" width={44} />
        <Tooltip {...tooltipStyles} formatter={(v, n) => [Number(v).toLocaleString(), n]} />
        <Area type="monotone" dataKey="total" stroke="#4f8ef7" strokeWidth={1.5} fill="url(#gTotal)" name="Total" />
        <Area type="monotone" dataKey="blocked" stroke="#f25c5c" strokeWidth={1.5} fill="url(#gBlock)" name="Blocked" />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function AttackTypesPie({ data }) {
  return (
    <ResponsiveContainer width="100%" height={180}>
      <PieChart>
        <Pie data={data} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="count" paddingAngle={2}>
          {data.map((e, i) => <Cell key={i} fill={e.color} opacity={0.9} />)}
        </Pie>
        <Tooltip {...tooltipStyles} formatter={(v, n) => [Number(v).toLocaleString(), n]} />
      </PieChart>
    </ResponsiveContainer>
  )
}
