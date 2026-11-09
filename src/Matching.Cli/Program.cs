using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Matching;

try
{
    if(args.Length==1 && args[0] is "help" or "version")
    {
        Console.WriteLine(args[0]=="version"?Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion:"Synthetic single-writer matching lab v1. run INPUT.jsonl NEW_OUTPUT_DIR [indexed|scan]; input <=8MiB, frame<=4096 UTF-8 bytes, commands<=20000. No network or persistent book.");return 0;
    }
    if(args.Length is <3 or >4 || args[0]!="run" || args.Length==4 && args[3] is not ("indexed" or "scan"))throw new ArgumentException("Use help");
    var input=Path.GetFullPath(args[1]);var destination=Path.GetFullPath(args[2]);if(new FileInfo(input).Length>8*1024*1024)throw new ArgumentException("Input cap");if(Directory.Exists(destination)||File.Exists(destination))throw new ArgumentException("Output must be fresh");
    byte[] bytes;using(var source=new FileStream(input,FileMode.Open,FileAccess.Read,FileShare.Read))
    {
        var buffer=new byte[8*1024*1024+1];int size=0;while(size<buffer.Length){int read=source.Read(buffer.AsSpan(size));if(read==0)break;size+=read;}if(size>8*1024*1024)throw new ArgumentException("Input cap");bytes=buffer.AsSpan(0,size).ToArray();
    }
    if(bytes.AsSpan().StartsWith(new byte[]{239,187,191}))throw new ArgumentException("BOM");
    var text=new UTF8Encoding(false,true).GetString(bytes);var lines=text.Split('\n');var count=lines.Length-(lines[^1]==""?1:0);if(count is <1 or >20000)throw new ArgumentException("Command count");
    var commands=new Command[count];for(int i=0;i<count;i++){var line=lines[i].EndsWith('\r')?lines[i][..^1]:lines[i];if(line.Length==0 || line.Contains('\r') || Encoding.UTF8.GetByteCount(line)>4096)throw new ArgumentException("Frame cap or framing");commands[i]=JsonSerializer.Deserialize<Command>(line,Wire.Options)??throw new ArgumentException("Null command");}
    IMatcher engine=args.Length==4 && args[3]=="scan"?new ScanMatcher():new IndexedMatcher();Directory.CreateDirectory(destination);var timer=Stopwatch.StartNew();long rawBytes=0;var raw=Path.Combine(destination,"events.incomplete.jsonl");
    using(var output=new FileStream(raw,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
    {
        for(int i=0;i<commands.Length;i++)
        {
            if(timer.Elapsed>TimeSpan.FromSeconds(60))throw new InvalidOperationException("Bounded replay deadline; incomplete output is not proof");
            var result=engine.Apply(commands[i]);var state=engine.Snapshot();var record=JsonSerializer.SerializeToUtf8Bytes(new{inputIndex=i+1,command=commands[i],result,stateHash=Contract.StateHash(state)},Wire.Options);rawBytes+=record.Length+1;if(rawBytes>32*1024*1024)throw new InvalidOperationException("Raw output cap; incomplete output is not proof");output.Write(record);output.WriteByte(10);
        }
    }
    var final=JsonSerializer.SerializeToUtf8Bytes(engine.Snapshot(),Wire.Options);if(final.Length>32*1024*1024)throw new InvalidOperationException("Snapshot cap");File.WriteAllBytes(Path.Combine(destination,"final.json"),final);File.Move(raw,Path.Combine(destination,"events.jsonl"));
    File.WriteAllText(Path.Combine(destination,"receipt.json"),JsonSerializer.Serialize(new{status="COMPLETE_NOT_INDEPENDENT_PROOF",sourceVersion=Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion,commands=count,implementation=args.Length==4?args[3]:"indexed",inputSha256=Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)),stateHash=Contract.StateHash(engine.Snapshot()),boundary="Fresh in-memory replay only; all per-command snapshots/hashes are evidence overhead, not a latency benchmark."},Wire.Options)+"\n",new UTF8Encoding(false));Console.WriteLine("COMPLETE_NOT_INDEPENDENT_PROOF");return 0;
}
catch(Exception error) when(error is ArgumentException or JsonException or IOException or UnauthorizedAccessException or DecoderFallbackException or InvalidOperationException)
{
    Console.Error.WriteLine("INCOMPLETE_OR_REJECTED: "+error.GetType().Name);return 2;
}
