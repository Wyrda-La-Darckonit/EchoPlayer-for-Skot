#pragma once
#include <iostream>
#include <cstdlib>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <stack>
#include <map>
#include <Windows.h>
#include <fstream>
#include <io.h>
#include <direct.h>

constexpr auto QUIT = -1;
constexpr auto PVT = 0;
constexpr auto GRP = 1;
constexpr auto DIS = 2;
constexpr auto ING = 3;

using namespace std;



///	【全局静态变量】

extern int ac;
static string _home_ = "data\\app\\skot\\";
static string usrDir = _home_ + "usr\\";
static string sudoerFile = _home_ + "sudoers.csv";
static string blackFile = _home_ + "blackList.csv";

//	错误：xxxxxx<str>xxxxxx。[recommand]
//class xx_exception : public exception {
//public: xx_exception(string str, string recommand = "") :
//	exception::exception(("错误：xxxxxx" + str + "xxxxxx。" + recommand).data()) {};
//};



///	【发送消息】

//	发送消息
void PostMsg(int type, int64_t target = 0, string msg = "")
{
	switch (type)
	{
	case PVT: CQ_sendPrivateMsg(ac, target, msg.data()); break;
	case GRP: CQ_sendGroupMsg(ac, target, msg.data()); break;
	case DIS: CQ_sendDiscussMsg(ac, target, msg.data()); break;
	}
	return;
}



///	【初始化】

//	创建必要的文件夹
void Init()
{
	if (_access(_home_.data(), 00) == -1) _mkdir(_home_.data());
	if (_access(usrDir.data(), 00) == -1) _mkdir(usrDir.data());
}



///	【异常】

//	错误：<str>不是合法的数字。
class str_not_num : public exception {
public: str_not_num(string str) :
	exception::exception(("错误：" + str + "不是合法的数字。").data()) {};
};
//	错误：参数<str>只在群/组内可用。[recommand]
class arg_used_in_pvt : public exception {
public: arg_used_in_pvt(string str, string recommand = "") :
	exception::exception(("错误：参数" + str + "只在群/组内可用。" + recommand).data()) {};
};
//	错误：<str>缺少必要的参数。[recommand]
class arg_not_found : public exception {
public: arg_not_found(string str, string recommand = "") :
	exception::exception(("错误：" + str + "缺少必要的参数。" + recommand).data()) {};
};
//	错误：参数<str>不合法。[recommand]
class arg_illegal : public exception {
public: arg_illegal(string str, string recommand = "") :
	exception::exception(("错误：参数" + str + "不合法。" + recommand).data()) {};
};
//	错误：参数<str>不能同时使用。[recommand]
class arg_use_same_time : public exception {
public: arg_use_same_time(string str, string recommand = "") :
	exception::exception(("错误：参数" + str + "不能同时使用。" + recommand).data()) {};
};
//	错误：<str>需要DM权限。[recommand]
class operator_is_not_dm : public exception {
public: operator_is_not_dm(string str, string recommand = "") :
	exception::exception(("错误：" + str + "需要DM权限。" + recommand).data()) {};
};



///	【指令与文件】

//	处理指令（包括进行转义）
vector<string> to_args(string cmd)
{
	vector<string> args;
	if (cmd.find("\r\n") != string::npos) cmd.erase(cmd.find("\r\n"));

	bool escape = false;
	bool quote = false;

	if (!cmd.empty()) args.push_back("");
	for (string::iterator D2 = cmd.begin(); D2 != cmd.end(); D2++)
	{
		if (escape)
		{
			if (*D2 == '\\' || *D2 == '-') args.back() += '\\', args.back() += *D2;
			else if (*D2 == 'n') args.back() += '\n';
			else args.back() += *D2;
			escape = false;
			continue;
		}
		switch (*D2)
		{
		case '\\':
			escape = true;
			continue;
		case '"':
			quote ^= true;
			continue;
		case '-':
			if (quote) args.back() += '\\';
			args.back() += *D2;
			continue;
		case ' ':
			if (quote) args.back() += *D2;
			else
			{
				for (; D2 + 1 != cmd.end() && *(D2 + 1) == ' '; D2++);
				if (D2 + 1 == cmd.end())
				{
					cmd.erase(D2);
					D2--;
					break;
				}
				args.push_back("");
			}
			continue;
		default:
			args.back() += *D2;
		}
	}
	return args;
}
//	解析指令转义
void anal(string& arg)
{
	bool escape = false;
	for (string::iterator D2 = arg.begin(); D2 != arg.end(); D2++)
	{
		if (*D2 == '\\')
		{
			if (escape) escape = false;
			else
			{
				escape = true;
				arg.erase(D2);
			}
		}
		else continue;
	}
	return;
}
//	单个值写入csv前进行转义
string to_csv(string str)
{
	string Ly = "";

	bool Sp = false;

	for (char D2 : str) switch (D2)
	{
	case '"': Ly += "\"";
	case ',': Sp = true;
	default: Ly += D2;
	}

	if (Sp) Ly = "\"" + Ly + "\"";

	return Ly;
}
//	分析csv文件行（包括解析csv转义）
vector<string> csv(string line)
{
	if (line.empty()) return vector<string>::vector();

	bool quote = false;
	bool escape = false;

	//	分割
	vector<string> cy;
	cy.push_back("");
	quote = false;
	escape = false;

	for (string::iterator D2 = line.begin(); D2 != line.end(); D2++) switch (*D2)
	{
	case ',':
		if (quote) cy.back() += *D2;
		else cy.push_back("");
		continue;
	case '"':
		if (escape) escape = false, cy.back() += '\"';
		else if (!quote && (D2 == line.begin() || *(D2 - 1) == ',')) quote = true;
		else if (quote && (D2 + 1 == line.end() || *(D2 + 1) == ',')) quote = false;
		else escape = true;
		continue;
	default:
		cy.back() += *D2;
	}
	return cy;
}



///	【cast】

//	将字符串转为整数
int64_t to_int(string str)
{
	int64_t Ly = 0;
	bool positive = true;

	int stat = 0;
	for (char D2 : str) switch (stat)
	{
	case 0:
		if (D2 == '+' || D2 == '-')
		{
			stat = 1;
			if (D2 == '-') positive = false;
		}
		else if ('0' <= D2 && D2 <= '9')
		{
			stat = 2;
			Ly *= 10;
			Ly += D2 - '0';
		}
		else throw (str_not_num(str));
		break;
	case 1:
		if ('0' <= D2 && D2 <= '9')
		{
			stat = 2;
			Ly *= 10;
			Ly += D2 - '0';
		}
		else throw (str_not_num(str));
		break;
	case 2:
		if ('0' <= D2 && D2 <= '9')
		{
			stat = 2;
			Ly *= 10;
			Ly += D2 - '0';
		}
		else if (D2 == '.') stat = 3;
		else throw (str_not_num(str));
		break;
	case 3:
		if ('0' <= D2 && D2 <= '9') stat = 4;
		else throw (str_not_num(str));
		break;
	case 4:
		if ('0' <= D2 && D2 <= '9') stat = 4;
		else throw (str_not_num(str));
		break;
	}
	if (stat == 2 || stat == 4)
	{
		if (!positive) Ly = -Ly;
		return Ly;
	}
	else throw (str_not_num(str));
}
//	将字符串转为小数
double to_double(string str)
{
	double Ly = 0;
	bool positive = true;
	int dot = 0;

	int stat = 0;
	for (char D2 : str) switch (stat)
	{
	case 0:
		if (D2 == '+' || D2 == '-')
		{
			stat = 1;
			if (D2 == '-') positive = false;
		}
		else if ('0' <= D2 && D2 <= '9')
		{
			stat = 2;
			Ly *= 10;
			Ly += D2 - '0';
		}
		else throw (str_not_num(str));
		break;
	case 1:
		if ('0' <= D2 && D2 <= '9')
		{
			stat = 2;
			Ly *= 10;
			Ly += D2 - '0';
		}
		else throw (str_not_num(str));
		break;
	case 2:
		if ('0' <= D2 && D2 <= '9')
		{
			stat = 2;
			Ly *= 10;
			Ly += D2 - '0';
		}
		else if (D2 == '.') stat = 3;
		else throw (str_not_num(str));
		break;
	case 3:
		if ('0' <= D2 && D2 <= '9')
		{
			stat = 4;
			Ly *= 10;
			Ly += D2 - '0';
			dot++;
		}
		else throw (str_not_num(str));
		break;
	case 4:
		if ('0' <= D2 && D2 <= '9')
		{
			stat = 4;
			Ly *= 10;
			Ly += D2 - '0';
			dot++;
		}
		else throw (str_not_num(str));
		break;
	}
	if (stat == 2 || stat == 4)
	{
		for (; dot != 0; dot--) Ly /= 10;
		if (!positive) Ly = -Ly;
		return Ly;
	}
	else throw (str_not_num(str));
}
//	将字符串转为qq（包括CQ码的@）
int64_t to_QQNumber(string str)
{
	if (str.find("[CQ:at,qq=") == 0 && *(str.end() - 1) == ']') str.erase(0, 10), str.erase(str.end() - 1);
	int64_t Ly = 0;
	try
	{
		Ly = to_int(str);
	}
	catch (str_not_num e)
	{
		Ly = -1;
	}
	return Ly;
}
//	@qq
string atQQ(int64_t QQ) { return "[CQ:at,qq=" + to_string(QQ) + "] "; }



///	【is?】

//	检查是否是合法的qq号（包括@）
bool is_QQNumber(string str)
{
	if (str.find("[CQ:at,qq=") == 0 && *(str.end() - 1) == ']') str.erase(0, 10), str.erase(str.end() - 1);
	int Fred = 0;
	for (char D2 : str)
	{
		if (D2 >= '0' && D2 <= '9') Fred++;
		else return false;
	}
	if (Fred > 10 || Fred < 5) return false;
	return true;
}
//	检查字符串是否是数字
bool is_num(string str)
{
	int stat = 0;
	for (char D2 : str) switch (stat)
	{
	case 0:
		if (D2 == '+' || D2 == '-') stat = 1;
		else if ('0' <= D2 && D2 <= '9') stat = 2;
		else return false;
		break;
	case 1:
		if ('0' <= D2 && D2 <= '9') stat = 2;
		else return false;
		break;
	case 2:
		if ('0' <= D2 && D2 <= '9') stat = 2;
		else if (D2 == '.') stat = 3;
		else return false;
		break;
	case 3:
		if ('0' <= D2 && D2 <= '9') stat = 4;
		else return false;
		break;
	case 4:
		if ('0' <= D2 && D2 <= '9') stat = 4;
		else return false;
		break;
	}
	if (stat == 2 || stat == 4) return true;
	else return false;
}



///	【类】

//	群组
class Group
{
	int64_t gid;
	vector<int64_t> dm;
	string CCC;

	bool stat;
	bool counter;
	int repeat;
	int repeatRate;
	int interrupt;
	int interruptRate;
	string s1;
	string s2;

	string toString()
	{
		string Ly = CCC;
		Ly += (string)"\necho," + (stat ? "1" : "0")
			+ "," + (counter ? "1" : "0")
			+ "," + to_string(repeat)
			+ "," + to_string(repeatRate)
			+ "," + to_string(interrupt)
			+ "," + to_string(interruptRate)
			+ "," + s1
			+ "," + s2;
		if (!Ly.empty()) Ly.erase(0, 1);
		return Ly;
	}

public:
	Group(int64_t gid)
	{
		this->gid = gid;
		stat = false;
		counter = false;
		repeat = 0;
		repeatRate = 10;
		interrupt = 1;
		interruptRate = 10;
		s1 = "打断复读";
		s2 = "学什么学";

		ifstream CH(usrDir + "g" + to_string(gid) + ".csv");
		bool Sp = false;
		string P2;
		if (CH.is_open())
		{
			vector<string> cy;
			for (; !CH.eof();)
			{
				getline(CH, P2); if (P2.empty()) continue;
				cy = csv(P2);
				if (cy[0]._Equal("dm")) dm.push_back(to_int(cy[1]));

				if (cy[0]._Equal("echo"))
				{
					if (cy.size() == 9)
					{
						Sp = true;
						stat = cy[1]._Equal("1");
						counter = cy[2]._Equal("1");
						repeat = to_int(cy[3]);
						repeatRate = to_int(cy[4]);
						interrupt = to_int(cy[5]);
						interruptRate = to_int(cy[6]);
						s1 = cy[7];
						s2 = cy[8];
					}
				}
				else CCC += "\n" + P2;
			}
			CH.close();
		}
	}
	~Group()
	{
		ofstream kx(usrDir + "g" + to_string(gid) + ".csv");
		if (kx.is_open())
		{
			kx << toString();
			kx.close();
		}
	}

	//	set
	void setStat(bool newStat) { stat = newStat; }
	void setCounter(bool newCounter) { counter = newCounter; }
	void setRepeat(int newRepeat) { repeat = newRepeat; }
	void setRepeatRate(int newRepeatRate) { repeatRate = newRepeatRate; }
	void setInterrupt(int newInterrupt) { interrupt = newInterrupt; }
	void setInterruptRate(int newInterruptRate) { interruptRate = newInterruptRate; }
	void setS1(string newS1) { s1 = newS1; }
	void setS2(string newS2) { s2 = newS2; }

	//	get
	bool getStat() { return stat; }
	bool getCounter() { return counter; }
	int getRepeat() { return repeat; }
	int getRepeatRate() { return repeatRate; }
	int getInterrupt() { return interrupt; }
	int getInterruptRate() { return interruptRate; }
	string getS1() { return s1; }
	string getS2() { return s2; }

	//	is?
	bool is_dm(int64_t qq)
	{
		for (vector<int64_t>::iterator D2 = dm.begin(); D2 != dm.end(); D2++)
			if (*D2 == qq) return true;
		return false;
	}
};



///	【紧急补丁】

//	黑名单
class BlackListUnit
{
public:
	string type;
	int64_t qq;
	int64_t gid;
	BlackListUnit(string str)
	{
		qq = gid = 0;
		vector<string> cy = csv(str);
		type = cy[0];
		if (type._Equal("user")) qq = to_int(cy[1]);
		if (type._Equal("group")) gid = to_int(cy[1]);
		if (type._Equal("inGroup")) gid = to_int(cy[1]), qq = to_int(cy[2]);
	}
};
class BlackList
{
	vector<BlackListUnit> list;
public:
	BlackList()
	{
		ifstream in(blackFile);
		if (in.is_open())
		{
			string P2;
			for (; !in.eof();)
			{
				getline(in, P2); if (P2.empty()) continue;
				list.push_back(BlackListUnit(P2));
			}
			in.close();
		}
	}
	bool contains(int64_t qq, int64_t gid)
	{
		for (auto D2 : list)
		{
			if (D2.type._Equal("user") && qq == D2.qq) return true;
			if (D2.type._Equal("group") && gid == D2.gid) return true;
			if (D2.type._Equal("inGroup") && qq == D2.qq && gid == D2.gid) return true;
		}
		return false;
	}
} blackList;



/// 【EchoPlayer】

class Record
{
public:
	string lastMessage;
	int repeatTime;
	bool repeated;
};
map<int64_t, Record> parakeet;

//	复读操作
void EchoPlayer(int type, int64_t gid, string msg)
{
	if (blackList.contains(0, gid)) return;

	srand(GetTickCount64());
	Group Where = Group(gid);

	//	复读机关闭
	if (!Where.getStat()) return;
	//	更新状态
	if (msg._Equal(parakeet[gid].lastMessage)) parakeet[gid].repeatTime++;
	else parakeet[gid].lastMessage = msg, parakeet[gid].repeated = false, parakeet[gid].repeatTime = 0;

	//	打断
	if (Where.getInterrupt() > 0 && parakeet[gid].repeatTime >= Where.getInterrupt() && Where.getInterruptRate() > rand() % 100)
	{
		if (!msg._Equal(Where.getS1())) parakeet[gid].lastMessage = Where.getS1(), PostMsg(type, gid, Where.getS1());
		else parakeet[gid].lastMessage = Where.getS2(), PostMsg(type, gid, Where.getS2());
		parakeet[gid].repeated = true, parakeet[gid].repeatTime = 0;
	}
	//	复读
	else if (!parakeet[gid].repeated && parakeet[gid].repeatTime >= Where.getRepeat() && Where.getRepeatRate() > rand() % 100)
	{
		if (Where.getCounter())
		{
			string tmpMsg = msg;
			vector<string> Fd
			{
				"。","，","！","？","；","～","（","）","《","》","【","】","…","—","“","”",
				".",",","!","?","(",")","<",">","[","]","{","}","-","~",",","*","\'","\""
			};
			for (auto D2 : Fd) for (; tmpMsg.find(D2) != string::npos; tmpMsg.erase(tmpMsg.find(D2), D2.length()));

			string testSpaceStr = "";
			for (auto D2 : tmpMsg) if (D2 != ' ') testSpaceStr += D2;

			if (!tmpMsg.empty() && !testSpaceStr.empty() && tmpMsg.length() < 4) msg = tmpMsg + "什么" + tmpMsg;
			parakeet[gid].lastMessage = msg, parakeet[gid].repeated = true, parakeet[gid].repeatTime = 0;
		}
		else parakeet[gid].repeated = true, parakeet[gid].repeatTime++;
		PostMsg(type, gid, msg);
	}
}



/// 【指令】

//	echo指令
string echo(bool sudo, int type, int64_t qq, int64_t gid, vector<string> args)
{
	string Ly = "";

	Group Where = Group(gid);
	bool Aur = sudo || Where.is_dm(qq);

	bool help = false;
	bool ver = false;
	bool src = false;
	bool list = false;
	vector<string> sets;

	for (int i = 1; i != args.size(); i++)
	{
		if (args.empty()) continue;
		if (args[i].find("-") == 0)
		{
			list = false;
			if (args[i]._Equal("--help")) help = true;
			else if (args[i]._Equal("--ver")) ver = true;
			else if (args[i]._Equal("--source")) src = true;
			else if (args[i]._Equal("--vs")) ver = src = true;
		}
		else
		{
			if (!Aur) throw (operator_is_not_dm("设置EchoPlayer"));
			anal(args[i]);
			sets.push_back(args[i]);
		}
	}

	if (type == PVT) return "错误：指令echo只能在群/组内使用。";

	if (args.size() == 1) list = true;

	if (help) return string("")
		+ "【用法】\n"
		+ ".echo\n显示EchoPlayer当前的状态。\n\n"
		+ "【参数】\n"
		+ (Aur ? "<属性>=<值>\n设置指定属性的值。详细设置方法请使用.echo ?查看。\n\n" : "")
		+ "--ver\n查看版本信息。\n\n"
		+ "--source\n获取源码。\n\n"
		+ "--help\n显示此信息。";

	if (ver || src) return string("")
		+ CQAPPID + " " + CQAPPVER + "\n"
		+ (ver ? "Copyright (C) 2019 Skot\n" : "")
		+ (ver ? "许可证：GPLv3+：GNU通用公共许可证第3版或更新版本<http://gnu.org/licenses/gpl.html>\n" : "")
		+ (ver ? "本软件是自由软件：您可以自由修改和重新发布它。\n" : "")
		+ (ver ? "在法律范围内没有其他保障。\n" : "")
		+ (ver ? "\n" : "")
		+ (ver ? "由 Wyrda La Darckonit (Westerm_Dragon@126.com) 编写。\n" : "")
		+ (src ? "源码：https://github.com/Wyrda-La-Darckonit/EchoPlayer-for-Skot.git" : "");

	if (list) return (string)"EchoPlayer当前状态：\n"
		+ "运行状态：" + (Where.getStat() ? "开启" : "关闭") + "\n"
		+ "反击模式：" + (Where.getCounter() ? "开启" : "关闭") + "\n"
		+ "触发计数：" + to_string(Where.getRepeat()) + "次复读\n"
		+ "触发概率：" + to_string(Where.getRepeatRate()) + "%\n"
		+ (Where.getInterrupt() == 0 ? "扰断功能关闭" : "")
		+ (Where.getInterrupt() == 0 ? "" : "扰断计数：" + to_string(Where.getInterrupt()) + "次复读\n")
		+ (Where.getInterrupt() == 0 ? "" : "扰断概率：" + to_string(Where.getInterruptRate()) + "%");

	if (sets.size() != 0)
	{
		for each (auto D2 in sets) if (D2._Equal("?") || D2._Equal("？")) return (string)"设置方法："
			+ "\n.echo <属性>=<值> [<属性>=<值>]"
			+ "\n"
			+ "\n可用属性："
			+ "\n运行状态：st/stat，控制EchoPlayer是否开启，应设定为on/off"
			+ "\n反击模式：ct/counter，控制反击模式是否开启，应设定为on/off"
			+ "\n触发计数：rt/repeat，指定至少经过多少次复读后才会触发EchoPlayer的复读，应设定为不小于0的整数"
			+ "\n触发概率：rr/rtrate，指定EchoPlayer复读的概率，应设定为最小为0最大为100的整数"
			+ "\n扰断计数：it/interrupt，指定至少经过多少次复读后才会触发EchoPlayer的扰断，应设定为不小于0的整数（见下文）"
			+ "\n扰断概率：ir/itrate，指定EchoPlayer扰断的概率，应设定为最小为0最大为100的整数"
			+ "\n扰断文本：s1，指定EchoPlayer扰断复读时所用的文本，可设定为任意文本"
			+ "\n备用文本：s2，指定当扰断文本被复读时EchoPlayer进行扰断所用的文本，可设定为任意文本，但不能与扰断文本重复"
			+ "\n"
			+ "\n注意事项："
			+ "\n反击模式是指，当被复读的消息很短（小于4个字节，大多数标点符号都不计入）时，EchoPlayer会发送“xx什么xx”来替代正常的复读。"
			+ "\n等于号“=”的左右两侧都不能有空格，否则会导致无法正常识别字段。"
			+ "\n触发计数与触发概率之间的关系为“与”，即只有在复读次数达到触发计数后，才会按照触发概率进行复读。扰断同理。"
			+ "\n当触发计数设定为0时，表示不需要产生复读即可触发，即每一条消息都会按照触发概率触发复读。若触发概率被设为100，则每一条消息都会被立即复读。"
			+ "\n当扰断计数设定为0时，扰断功能会关闭，这是因为当没有形成复读时不应予以扰断。若要使用扰断功能，扰断计数应至少设定为1。"
			+ "\n当触发计数和扰断计数都被满足时，优先进行扰断判定。例如，扰断概率为80%，复读概率为40%时，实际响应情况为，扰断80%，复读8%，不响应12%。"
			+ "\n"
			+ "\n示例："
			+ "\n.echo stat=on"
			+ "\n开启EchoPlayer。"
			+ "\n.echo repeat=0 rtrate=20"
			+ "\n设置触发计数为0，触发概率为20%；每条消息都有20%的几率触发复读。"
			+ "\n.echo rt=1 rr=100 it=3 ir=50 ct=on"
			+ "\n当一条消息被复读1次后，100%概率跟读；当这条消息被复读3次后（EchoPlayer本身的复读也被计入），50%概率扰断；开启反击模式。";
		
		string key;
		string fail;
		bool edit[8] = { false };
		int val;
		string str;

		for each (auto D2 in sets)
		{
			if (D2.find("=") == string::npos || D2.find("=") == 0)
			{
				fail += "；\n无法识别字段“" + D2 + "”";
				continue;
			}

			key = D2.substr(0, D2.find("="));
			for (auto Fd = key.begin(); Fd != key.end(); Fd++) if ('A' <= *Fd && *Fd <= 'Z')* Fd += 'a' - 'A';

			if (key._Equal("st") || key._Equal("stat"))
			{
				str = D2.substr(D2.find("=") + 1);
				for (auto Fd = str.begin(); Fd != str.end(); Fd++) if ('A' <= *Fd && *Fd <= 'Z')* Fd += 'a' - 'A';
				if (str.empty()) fail += "；\n需要为运行状态设定一个值（on/off）";
				else if (str._Equal("on") || str._Equal("1")) Where.setStat(true), edit[0] = true;
				else if (str._Equal("off") || str._Equal("0")) Where.setStat(false), edit[0] = true;
				else fail += "；\n运行状态应该设定为on/off";
			}
			else if (key._Equal("ct") || key._Equal("counter"))
			{
				str = D2.substr(D2.find("=") + 1);
				for (auto Fd = str.begin(); Fd != str.end(); Fd++) if ('A' <= *Fd && *Fd <= 'Z')* Fd += 'a' - 'A';
				if (str.empty()) fail += "；\n需要为反击模式设定一个值（on/off）";
				else if (str._Equal("on") || str._Equal("1")) Where.setCounter(true), edit[1] = true;
				else if (str._Equal("off") || str._Equal("0")) Where.setCounter(false), edit[1] = true;
				else fail += "；\n反击模式应该设定为on/off";
			}
			else if (key._Equal("rt") || key._Equal("repeat"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "；\n需要为触发计数设定一个值（非负整数）";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "；n触发计数不应小于0";
					else Where.setRepeat(val), edit[2] = true;
				}
				catch (str_not_num e)
				{
					fail += "；\n触发计数应该设定为非负整数";
				}
			}
			else if (key._Equal("rtrate") || key._Equal("rr"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "；\n需要为触发概率设定一个值（0-100）";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "；\n触发概率不应小于0";
					else if (val > 100) fail += "；\n触发概率不应大于100";
					else Where.setRepeatRate(val), edit[3] = true;
				}
				catch (str_not_num e)
				{
					fail += "；\n触发概率应该设定最小为0，最大为100的整数";
				}
			}
			else if (key._Equal("it") || key._Equal("interrupt"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "；\n需要为扰断计数设定一个值（不小于0的整数）";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "；n扰断计数不应小于0";
					else Where.setInterrupt(val), edit[4] = true;
				}
				catch (str_not_num e)
				{
					fail += "；n扰断计数应该设定为不小于0的整数";
				}
			}
			else if (key._Equal("itrate") || key._Equal("ir"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "；\n需要为扰断概率设定一个值（0-100）";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "；\n扰断概率不应小于0";
					else if (val > 100) fail += "；\n扰断概率不应大于100";
					else Where.setInterruptRate(val), edit[5] = true;
				}
				catch (str_not_num e)
				{
					fail += "；n扰断概率应该设定最小为0，最大为100的整数";
				}
			}
			else if (key._Equal("s1"))
			{
				str = D2.substr(D2.find("=") + 1);
				if (str.empty()) fail += "；\n需要为扰断文本设定一个值（任意文本）";
				else Where.setS1(str), edit[6] = true;
			}
			else if (key._Equal("s2"))
			{
				str = D2.substr(D2.find("=") + 1);
				if (str.empty()) fail += "\n需要为备用文本设定一个值（任意文本）。";
				else Where.setS2(str), edit[7] = true;
			}
			else fail += "；\n没有此属性：" + key;
		}
		if (!fail.empty()) fail.erase(0, 2), fail += "。";

		if (Where.getS1()._Equal(Where.getS2()))
		{
			edit[7] = true;
			if (!Where.getS1()._Equal("学什么学")) Where.setS2("学什么学");
			else Where.setS2("打断复读");
		}

		for (int i = 0; i != 8; i++) if (edit[i]) switch (i)
		{
		case 0: Ly += (string)"；\nEchoPlayer" + (Where.getStat() ? "开启" : "关闭"); break;
		case 1: Ly += (string)"；\n反击模式" + (Where.getCounter() ? "开启" : "关闭"); break;
		case 2: Ly += "；\n触发计数设定为" + to_string(Where.getRepeat()); break;
		case 3: Ly += "；\n触发概率设定为" + to_string(Where.getRepeatRate()) + "%"; break;
		case 4: Ly += (Where.getInterrupt() == 0 ? "；\n扰断功能关闭" : "；\n扰断计数设定为" + to_string(Where.getInterrupt())); break;
		case 5: Ly += (Where.getInterrupt() == 0 ? "" : "；\n扰断概率设定为" + to_string(Where.getInterruptRate()) + "%"); break;
		case 6: Ly += (Where.getInterrupt() == 0 ? "" : "；\n扰断文本设定为“" + Where.getS1() + "”"); break;
		case 7: Ly += (Where.getInterrupt() == 0 ? "" : "；\n备用文本设定为“" + Where.getS2() + "”"); break;
		}
		if (!Ly.empty()) Ly.erase(0, 3), Ly += "。";
		if (!fail.empty()) Ly += fail;
	}

	return Ly;
}



///	【入口点】

//	处理线程入口点
void run_main(int type, int64_t qq, int64_t gid, string msg)
{
	if (blackList.contains(qq, gid)) return;

	srand(GetTickCount64());

	string Ly = "";
	string sudoStr = "";
	bool sudo = msg.find("sudo") == 0;
	msg.erase(0, (sudo ? 6 : 1));
	if (msg.empty()) return;

	vector<string> args = to_args(msg);
	if (false);
	else if (args[0]._Equal("echo"));
	else return;

	if (sudo)
	{
		sudo = false;
		string P2 = "";
		string CCC = "";

		ifstream in(sudoerFile);
		if (in.is_open())
		{
			vector<string> cy;
			for (; !in.eof();)
			{
				getline(in, P2); if (P2.empty()) continue; cy = csv(P2);
				if (cy[0]._Equal(to_string(qq)))
				{
					sudo = true;
					if (cy.size() != 1) sudoStr = (string)"我们信任您已经从负责人那里了解了D20的注意事项。"
						+ "\n总结起来无外乎这三点："
						+ "\n"
						+ "\n    #1) 尊重别人的意愿。"
						+ "\n    #2) 考虑好后果和风险。"
						+ "\n    #3) 权力越大，责任越大。"
						+ "\n"
						+ "\n[sudo] ";
					else sudoStr = "[sudo] ";
					CCC += "\n" + cy[0];
				}
				else CCC += "\n" + P2;
			}
			in.close();
		}

		if (!CCC.empty())
		{
			CCC.erase(0, 1);
			ofstream out(sudoerFile);
			if (out.is_open())
			{
				out << CCC;
				out.close();
			}
		}

		if (!sudo) return;
	}

	if (sudo) try
	{
		bool as = false;
		bool asG = false;
		bool asD = false;
		bool asP = false;

		/*  id = 0  */	int64_t asQQ = -1;
		/*  id = 1  */	int64_t asinGroup = -1;
		/*  id = 2  */	int64_t asinDiscuss = -1;

		stack<int> ACP;
		for (auto it = args.begin() + 1; it != args.end(); it++)
		{
			if ((*it).find("-") == 0)
			{
				if ((*it)._Equal("-as")) args.erase(it--), as = true, ACP.push(0);
				else if ((*it)._Equal("-asg")) args.erase(it--), asG = true, ACP.push(1);
				else if ((*it)._Equal("-asd")) args.erase(it--), asD = true, ACP.push(2);
				else if ((*it)._Equal("-asp")) args.erase(it--), asP = true;

				if (asG && asD || asG && asP || asD && asP)
					throw (arg_illegal("-asg、-asd、-asp", "这三个参数只能同时使用一个。"));
			}
			else
			{
				if (!ACP.empty())
				{
					anal(*it);
					switch (ACP.top())
					{
					case 0:
						if (!is_QQNumber(*it))
							throw (arg_illegal("(-as)" + *it, "请更正为正确的QQ号码，或者直接@成员。"));
						asQQ = to_QQNumber(*it);
						args.erase(it--);
						break;
					case 1:
						if (!is_QQNumber(*it))
							throw (arg_illegal("(-asg)" + *it, "请更正为正确的群号码。"));
						asinGroup = to_QQNumber(*it);
						args.erase(it--);
						break;
					case 2:
						if (!is_QQNumber(*it))
							throw (arg_illegal("(-asd)" + *it, "请更正为正确的组号码。"));
						asinGroup = to_QQNumber(*it);
						args.erase(it--);
						break;
					}
					ACP.pop();
				}
			}
		}
		if (as && asQQ == -1)
			throw (arg_not_found("参数-as", string("") + "请指定QQ号码" + (type == PVT ? "" : "，或者直接@成员") + "。"));
		if (asG && asinGroup == -1)
			throw (arg_not_found("参数-asg", string("") + "请指定群号码。"));
		if (asD && asinDiscuss == -1)
			throw (arg_not_found("参数-asd", string("") + "请指定组号码。"));

		if (as) qq = asQQ;
		if (asinGroup != -1) type = GRP, gid = asinGroup;
		if (asinDiscuss != -1) type = DIS, gid = asinGroup;
	}
	catch (exception Ed)
	{
		PostMsg(type, (type == PVT ? qq : gid), Ed.what());
		return;
	}

	try
	{
		if (args[0]._Equal("echo")) Ly += echo(sudo, type, qq, gid, args);
	}
	catch (exception Ed)
	{
		Ly += Ed.what();
	}

	if (Ly.empty()) return;

	if (*(Ly.end() - 1) == '\n') Ly.erase(Ly.end() - 1);
	if (*Ly.begin() == '\n') Ly.erase(0, 1);
	if (sudo) Ly = sudoStr + Ly;
	PostMsg(type, (type == PVT ? qq : gid), Ly);
	return;
}