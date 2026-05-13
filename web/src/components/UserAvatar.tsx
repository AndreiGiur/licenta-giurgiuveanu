type Props = {
  email: string;
  pictureUrl?: string | null;
  size?: number;
};

export function UserAvatar({ email, pictureUrl, size = 32 }: Props) {
  const initial = email.charAt(0).toUpperCase();
  const style = {
    width: size,
    height: size,
    borderRadius: "50%",
    fontSize: Math.max(11, size * 0.4),
  };

  if (pictureUrl) {
    return (
      <img
        src={pictureUrl}
        alt={email}
        className="user-avatar"
        style={style}
        referrerPolicy="no-referrer"
      />
    );
  }
  return (
    <div className="user-avatar user-avatar-initial" style={style}>
      {initial}
    </div>
  );
}
