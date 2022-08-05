using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

//
// Repro program for aspnetcore #42877
//
// Creates and exports a certificate similar to how dev-certs does on macOS.
// THIS IS FOR DIAGNOSTIC PURPOSES AND IS NOT MEANT FOR REAL USE.
//
var cert = Repro.CreateCertificate();
Repro.ExportCertificate(cert);

public class Repro
{
    internal const int CurrentAspNetCoreCertificateVersion = 2;
    internal const string AspNetHttpsOid = "1.3.6.1.4.1.311.84.1.1";
    internal const string AspNetHttpsOidFriendlyName = "ASP.NET Core HTTPS development certificate";

    private const string ServerAuthenticationEnhancedKeyUsageOid = "1.3.6.1.5.5.7.3.1";
    private const string ServerAuthenticationEnhancedKeyUsageOidFriendlyName = "Server Authentication";

    private const string LocalhostHttpsDnsName = "localhost";
    private const string LocalhostHttpsDistinguishedName = "CN=" + LocalhostHttpsDnsName;
    
    public const int RSAMinimumKeySizeInBits = 2048;

    public static X509Certificate2 CreateCertificate()
    {
        // shims
        var notBefore = DateTime.Now;
        var notAfter = DateTime.Now + TimeSpan.FromDays(365);
        var Subject = LocalhostHttpsDistinguishedName;
        var AspNetHttpsCertificateVersion = CurrentAspNetCoreCertificateVersion;


        var subject = new X500DistinguishedName(Subject);
        var extensions = new List<X509Extension>();
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(LocalhostHttpsDnsName);

        var keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, critical: true);
        var enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
            new OidCollection() {
                new Oid(
                    ServerAuthenticationEnhancedKeyUsageOid,
                    ServerAuthenticationEnhancedKeyUsageOidFriendlyName)
            },
            critical: true);

        var basicConstraints = new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true);

        byte[] bytePayload;

        if (AspNetHttpsCertificateVersion != 0)
        {
            bytePayload = new byte[1];
            bytePayload[0] = (byte)AspNetHttpsCertificateVersion;
        }
        else
        {
            bytePayload = Encoding.ASCII.GetBytes(AspNetHttpsOidFriendlyName);
        }

        var aspNetHttpsExtension = new X509Extension(
            new AsnEncodedData(
                new Oid(AspNetHttpsOid, AspNetHttpsOidFriendlyName),
                bytePayload),
            critical: false);

        extensions.Add(basicConstraints);
        extensions.Add(keyUsage);
        extensions.Add(enhancedKeyUsage);
        extensions.Add(sanBuilder.Build(critical: true));
        extensions.Add(aspNetHttpsExtension);

        var certificate = CreateSelfSignedCertificate(subject, extensions, notBefore, notAfter);
        return certificate;
    }

    internal static X509Certificate2 CreateSelfSignedCertificate(
            X500DistinguishedName subject,
            IEnumerable<X509Extension> extensions,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter)
    {
        using var key = CreateKeyMaterial(RSAMinimumKeySizeInBits);

        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        var result = request.CreateSelfSigned(notBefore, notAfter);
        return result;

        RSA CreateKeyMaterial(int minimumKeySize)
        {
            var rsa = RSA.Create(minimumKeySize);
            if (rsa.KeySize < minimumKeySize)
            {
                throw new InvalidOperationException($"Failed to create a key with a size of {minimumKeySize} bits");
            }

            return rsa;
        }
    }

    public static void ExportCertificate(X509Certificate2 certificate)
    {
        var passwordBytes = new byte[48];
        RandomNumberGenerator.Fill(passwordBytes.AsSpan()[0..35]);
        var password = Convert.ToBase64String(passwordBytes, 0, 36);
        var certBytes = certificate.Export(X509ContentType.Pfx, password);
        var certificatePath = Path.GetTempFileName();
        Console.WriteLine("Certificate Path: " + certificatePath);

        File.WriteAllBytes(certificatePath, certBytes);

        var command = $"security import {certificatePath} -k "+
        Environment.GetEnvironmentVariable("HOME") + 
        $"/Library/Keychains/login.keychain-db -t cert -f pkcs12 -P {password} -A";
        
        Console.WriteLine("Run this command to add the certificate to your user keychain. Don't forget to delete it afterwards."
        + Environment.NewLine + Environment.NewLine + $"{command}"+ Environment.NewLine);
    }
}