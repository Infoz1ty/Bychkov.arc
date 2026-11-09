namespace SmartSecureArchiver.Core.Security;

public readonly record struct DerivedKeys(byte[] EncKey, byte[] MacKey);
