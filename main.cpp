#include "packet_analyzer.h"
using namespace std;

PacketAnalyzer analyzer;

void addTracesFromFolderList(string fl){
    ifstream traceList(fl.c_str());
	string s;
	while (getline(traceList, s)) {
	    s+="/arodata/traffic.cap";
		analyzer.addTrace(s);
	}
	traceList.close();
}


int main() {
//	string traceList("/home/alfred/Project/TMobile/Facebook/tracelist");
//ls -d $PWD/*
	addTracesFromFolderList("/home/alfred/Project/TMobile/Facebook/aro/traceList");



//	analyzer.setTraceListFileName(traceList);
	analyzer.init();
	analyzer.run();


	return 0;
}
