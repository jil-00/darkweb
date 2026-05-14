import { LineChart, Line, ResponsiveContainer } from "recharts";

interface SparklineProps {
  data: Array<{ value: number; [key: string]: any }>;
  dataKey?: string;
  color?: string;
  height?: number;
}

export function Sparkline({
  data,
  dataKey = "value",
  color = "#3B82F6",
  height = 40
}: SparklineProps) {
  if (!data || data.length === 0) {
    return <div style={{ height }} className="bg-gray-100 rounded" />;
  }

  return (
    <div className="kpi-sparkline">
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data}>
          <Line
            type="monotone"
            dataKey={dataKey}
            stroke={color}
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
