export default function StatCard({
  title,
  value,
  icon,
  color,
  isText,
}: {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  isText?: boolean;
}) {
  return (
    <div className="border border-[#2D2D2D] px-4 py-3.5 rounded-[4px] text-[#D6D5D4] hover:bg-[#1A1A1A] transition-colors group ">
      <div className="flex items-start justify-between mb-2">
        <div 
          className=" flex items-center justify-center "
          style={{ color: isText ? color : undefined }}
        >
          {icon}
        </div>
      </div>

      <div>
        <p className="text-[17px]  text-[#E7E7E7] mb-0.5" style={isText ? { color } : undefined}>
          {value}
        </p>
        <p className="text-[10px] text-[#797979] uppercase tracking-wide">{title}</p>
      </div>
    </div>
  );
}
