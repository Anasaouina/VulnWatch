import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { label?: string };

function Icon({
  paths,
  label,
  ...rest
}: IconProps & { paths: string[] }) {
  const px = {
    width: 18,
    height: 18,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": label ? undefined : true,
    role: label ? "img" : undefined,
    ...rest,
  };
  return (
    <svg {...px}>
      <title>{label}</title>
      {paths.map((path, i) => (
        <path key={i} d={path} />
      ))}
    </svg>
  );
}

export function ShieldIcon(props: IconProps) {
  return (
    <Icon
      label={props.label}
      paths={[
        "M12 3l7 3v5c0 4.5-3 8.2-7 9.5C8 19.2 5 15.5 5 11V6l7-3z",
        "M9.5 12l1.8 1.8L15 10",
      ]}
      {...props}
    />
  );
}

export function HomeIcon(props: IconProps) {
  return <Icon paths={["M4 11l8-7 8 7", "M6 10v9h12v-9"]} {...props} />;
}

export function ListIcon(props: IconProps) {
  return (
    <Icon
      paths={[
        "M8 6h12",
        "M8 12h12",
        "M8 18h12",
        "M4 6h.01",
        "M4 12h.01",
        "M4 18h.01",
      ]}
      {...props}
    />
  );
}

export function StarIcon(props: IconProps) {
  return (
    <Icon
      paths={[
        "M12 3l2.7 5.6 6.3.8-4.6 4.3 1.1 6.1L12 17l-5.5 2.8 1.1-6.1L3 9.4l6.3-.8L12 3z",
      ]}
      {...props}
    />
  );
}

export function AlertTriangleIcon(props: IconProps) {
  return (
    <Icon
      paths={[
        "M12 4l9 15H3l9-15z",
        "M12 10v4",
        "M12 17h.01",
      ]}
      {...props}
    />
  );
}

export function RssIcon(props: IconProps) {
  return (
    <Icon
      paths={[
        "M5 19h.01",
        "M5 12a7 7 0 0 1 7 7",
        "M5 5a14 14 0 0 1 14 14",
      ]}
      {...props}
    />
  );
}

export function SearchIcon(props: IconProps) {
  return (
    <Icon
      paths={[
        "M11 4a7 7 0 1 1-7 7 7 7 0 0 1 7-7z",
        "M21 21l-4.3-4.3",
      ]}
      {...props}
    />
  );
}

export function RefreshIcon(props: IconProps) {
  return (
    <Icon
      paths={[
        "M20 11a8 8 0 1 0-2.3 6.3",
        "M20 5v6h-6",
      ]}
      {...props}
    />
  );
}

export function TrashIcon(props: IconProps) {
  return (
    <Icon
      paths={[
        "M4 7h16",
        "M9 7V4h6v3",
        "M6 7l1 13h10l1-13",
        "M10 11v6",
        "M14 11v6",
      ]}
      {...props}
    />
  );
}

export function ChevronLeftIcon(props: IconProps) {
  return <Icon paths={["M15 5l-7 7 7 7"]} {...props} />;
}

export function ChevronRightIcon(props: IconProps) {
  return <Icon paths={["M9 5l7 7-7 7"]} {...props} />;
}

export function MenuIcon(props: IconProps) {
  return (
    <Icon
      paths={["M4 6h16", "M4 12h16", "M4 18h16"]}
      {...props}
    />
  );
}

export function ArrowLeftIcon(props: IconProps) {
  return <Icon paths={["M19 12H5", "M11 18l-6-6 6-6"]} {...props} />;
}
