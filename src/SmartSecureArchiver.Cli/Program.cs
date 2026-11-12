namespace SmartSecureArchiver.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("SmartSecureArchiver SARC v1 CLI");
            Console.WriteLine("Використання:");
            Console.WriteLine("  archive -i <files...> -o <output.arc> -p <password>");
            Console.WriteLine("  extract -a <volumes...> -o <output_dir> -p <password>");
            return 0;
        }

        return 0;
    }
}
