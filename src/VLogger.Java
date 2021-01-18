import java.io.*;
import java.util.*;
import java.text.*;

enum LogMesType {INFO, WARNING, ERROR}

class VLogger {
	
	public String Project = "", LogDir = ".\\Log", LogFile = "";
	
	public void writeMes(LogMesType eType, String sMes) {
		String sFormattedMes = "";
		Date dt = new Date();
		SimpleDateFormat df = new SimpleDateFormat("dd.MM.yy HH:mm:ss");
		FileWriter fw;
		
		switch(eType) {
		case INFO:
			sFormattedMes = df.format(dt)+"\tINF\t"+sMes+"\n";
			break;
		case WARNING:
			sFormattedMes = df.format(dt)+"\tWRN\t"+sMes+"\n";
			break;
		case ERROR:
			sFormattedMes = df.format(dt)+"\tERR\t"+sMes+"\n";
			break;
		}
		
		try {
			fw = new FileWriter(this.LogFile, true);
			fw.write(sFormattedMes, 0, sFormattedMes.length());
			fw.flush();
			fw.close();
			System.out.println(sMes);
		}
		catch(IOException e) {
			System.out.print("Exception" + e);
			return;
		}
	}
	
	public int init(String sProject) {
		Date dt = new Date();
		SimpleDateFormat df = new SimpleDateFormat("yyMMdd");
		
		this.Project = sProject;
		this.LogFile = this.LogDir+"\\"+this.Project+"_"+df.format(dt)+".log";
		
		try {
			this.mkDir();
		}
		catch(IOException e) {
			System.out.print("Exception" + e);
			return -1;
		}
		return 0;
	}
	
	private void mkDir() throws IOException {
		File f = new File(this.LogDir);
		f.mkdirs();
	}
	
}
