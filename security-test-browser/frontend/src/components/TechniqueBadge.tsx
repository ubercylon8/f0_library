interface TechniqueBadgeProps {
  technique: string;
}

export default function TechniqueBadge({ technique }: TechniqueBadgeProps) {
  return (
    <span className="inline-flex items-center px-2 py-1 rounded-md bg-primary/10 text-primary text-xs font-mono font-medium">
      {technique}
    </span>
  );
}
