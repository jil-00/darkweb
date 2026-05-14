interface RadialProgressRingProps {
  value: number;
  max?: number;
  color?: string;
  label?: string;
  size?: number;
}

export function RadialProgressRing({
  value,
  max = 100,
  color = "#3B82F6",
  label,
  size = 100
}: RadialProgressRingProps) {
  const radius = (size - 4) / 2;
  const circumference = radius * 2 * Math.PI;
  const percentage = Math.min((value / max) * 100, 100);
  const offset = circumference - (percentage / 100) * circumference;

  return (
    <div className="radial-progress">
      <div className="radial-progress-ring" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#E2E8F0"
            strokeWidth="3"
          />
          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="3"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 0.5s ease" }}
          />
        </svg>
        <div className="radial-progress-value">
          <span className="radial-progress-value-main">{value.toFixed(0)}</span>
          {label && <span className="radial-progress-value-label">{label}</span>}
        </div>
      </div>
    </div>
  );
}
