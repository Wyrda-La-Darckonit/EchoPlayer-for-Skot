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



///	��ȫ�־�̬������

extern int ac;
static string _home_ = "data\\app\\skot\\";
static string usrDir = _home_ + "usr\\";
static string sudoerFile = _home_ + "sudoers.csv";
static string blackFile = _home_ + "blackList.csv";

//	����xxxxxx<str>xxxxxx��[recommand]
//class xx_exception : public exception {
//public: xx_exception(string str, string recommand = "") :
//	exception::exception(("����xxxxxx" + str + "xxxxxx��" + recommand).data()) {};
//};



///	��������Ϣ��

//	������Ϣ
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



///	����ʼ����

//	������Ҫ���ļ���
void Init()
{
	if (_access(_home_.data(), 00) == -1) _mkdir(_home_.data());
	if (_access(usrDir.data(), 00) == -1) _mkdir(usrDir.data());
}



///	���쳣��

//	����<str>���ǺϷ������֡�
class str_not_num : public exception {
public: str_not_num(string str) :
	exception::exception(("����" + str + "���ǺϷ������֡�").data()) {};
};
//	���󣺲���<str>ֻ��Ⱥ/���ڿ��á�[recommand]
class arg_used_in_pvt : public exception {
public: arg_used_in_pvt(string str, string recommand = "") :
	exception::exception(("���󣺲���" + str + "ֻ��Ⱥ/���ڿ��á�" + recommand).data()) {};
};
//	����<str>ȱ�ٱ�Ҫ�Ĳ�����[recommand]
class arg_not_found : public exception {
public: arg_not_found(string str, string recommand = "") :
	exception::exception(("����" + str + "ȱ�ٱ�Ҫ�Ĳ�����" + recommand).data()) {};
};
//	���󣺲���<str>���Ϸ���[recommand]
class arg_illegal : public exception {
public: arg_illegal(string str, string recommand = "") :
	exception::exception(("���󣺲���" + str + "���Ϸ���" + recommand).data()) {};
};
//	���󣺲���<str>����ͬʱʹ�á�[recommand]
class arg_use_same_time : public exception {
public: arg_use_same_time(string str, string recommand = "") :
	exception::exception(("���󣺲���" + str + "����ͬʱʹ�á�" + recommand).data()) {};
};
//	����<str>��ҪDMȨ�ޡ�[recommand]
class operator_is_not_dm : public exception {
public: operator_is_not_dm(string str, string recommand = "") :
	exception::exception(("����" + str + "��ҪDMȨ�ޡ�" + recommand).data()) {};
};



///	��ָ�����ļ���

//	����ָ���������ת�壩
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
//	����ָ��ת��
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
//	����ֵд��csvǰ����ת��
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
//	����csv�ļ��У���������csvת�壩
vector<string> csv(string line)
{
	if (line.empty()) return vector<string>::vector();

	bool quote = false;
	bool escape = false;

	//	�ָ�
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



///	��cast��

//	���ַ���תΪ����
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
//	���ַ���תΪС��
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
//	���ַ���תΪqq������CQ���@��
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



///	��is?��

//	����Ƿ��ǺϷ���qq�ţ�����@��
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
//	����ַ����Ƿ�������
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



///	���ࡿ

//	Ⱥ��
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
		s1 = "��ϸ���";
		s2 = "ѧʲôѧ";

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



///	������������

//	������
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



/// ��EchoPlayer��

class Record
{
public:
	string lastMessage;
	int repeatTime;
	bool repeated;
};
map<int64_t, Record> parakeet;

//	��������
void EchoPlayer(int type, int64_t gid, string msg)
{
	if (blackList.contains(0, gid)) return;

	srand(GetTickCount64());
	Group Where = Group(gid);

	//	�������ر�
	if (!Where.getStat()) return;
	//	����״̬
	if (msg._Equal(parakeet[gid].lastMessage)) parakeet[gid].repeatTime++;
	else parakeet[gid].lastMessage = msg, parakeet[gid].repeated = false, parakeet[gid].repeatTime = 0;

	//	���
	if (Where.getInterrupt() > 0 && parakeet[gid].repeatTime >= Where.getInterrupt() && Where.getInterruptRate() > rand() % 100)
	{
		if (!msg._Equal(Where.getS1())) parakeet[gid].lastMessage = Where.getS1(), PostMsg(type, gid, Where.getS1());
		else parakeet[gid].lastMessage = Where.getS2(), PostMsg(type, gid, Where.getS2());
		parakeet[gid].repeated = true, parakeet[gid].repeatTime = 0;
	}
	//	����
	else if (!parakeet[gid].repeated && parakeet[gid].repeatTime >= Where.getRepeat() && Where.getRepeatRate() > rand() % 100)
	{
		if (Where.getCounter())
		{
			string tmpMsg = msg;
			vector<string> Fd
			{
				"��","��","��","��","��","��","��","��","��","��","��","��","��","��","��","��",
				".",",","!","?","(",")","<",">","[","]","{","}","-","~",",","*","\'","\""
			};
			for (auto D2 : Fd) for (; tmpMsg.find(D2) != string::npos; tmpMsg.erase(tmpMsg.find(D2), D2.length()));

			string testSpaceStr = "";
			for (auto D2 : tmpMsg) if (D2 != ' ') testSpaceStr += D2;

			if (!tmpMsg.empty() && !testSpaceStr.empty() && tmpMsg.length() < 4) msg = tmpMsg + "ʲô" + tmpMsg;
			parakeet[gid].lastMessage = msg, parakeet[gid].repeated = true, parakeet[gid].repeatTime = 0;
		}
		else parakeet[gid].repeated = true, parakeet[gid].repeatTime++;
		PostMsg(type, gid, msg);
	}
}



/// ��ָ�

//	echoָ��
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
			if (!Aur) throw (operator_is_not_dm("����EchoPlayer"));
			anal(args[i]);
			sets.push_back(args[i]);
		}
	}

	if (type == PVT) return "����ָ��echoֻ����Ⱥ/����ʹ�á�";

	if (args.size() == 1) list = true;

	if (help) return string("")
		+ "���÷���\n"
		+ ".echo\n��ʾEchoPlayer��ǰ��״̬��\n\n"
		+ "��������\n"
		+ (Aur ? "<����>=<ֵ>\n����ָ�����Ե�ֵ����ϸ���÷�����ʹ��.echo ?�鿴��\n\n" : "")
		+ "--ver\n�鿴�汾��Ϣ��\n\n"
		+ "--source\n��ȡԴ�롣\n\n"
		+ "--help\n��ʾ����Ϣ��";

	if (ver || src) return string("")
		+ CQAPPID + " " + CQAPPVER + "\n"
		+ (ver ? "Copyright (C) 2019 Skot\n" : "")
		+ (ver ? "���֤��GPLv3+��GNUͨ�ù������֤��3�����°汾<http://gnu.org/licenses/gpl.html>\n" : "")
		+ (ver ? "���������������������������޸ĺ����·�������\n" : "")
		+ (ver ? "�ڷ��ɷ�Χ��û���������ϡ�\n" : "")
		+ (ver ? "\n" : "")
		+ (ver ? "�� Wyrda La Darckonit (Westerm_Dragon@126.com) ��д��\n" : "")
		+ (src ? "Դ�룺https://github.com/Wyrda-La-Darckonit/EchoPlayer-for-Skot.git" : "");

	if (list) return (string)"EchoPlayer��ǰ״̬��\n"
		+ "����״̬��" + (Where.getStat() ? "����" : "�ر�") + "\n"
		+ "����ģʽ��" + (Where.getCounter() ? "����" : "�ر�") + "\n"
		+ "����������" + to_string(Where.getRepeat()) + "�θ���\n"
		+ "�������ʣ�" + to_string(Where.getRepeatRate()) + "%\n"
		+ (Where.getInterrupt() == 0 ? "�ŶϹ��ܹر�" : "")
		+ (Where.getInterrupt() == 0 ? "" : "�Ŷϼ�����" + to_string(Where.getInterrupt()) + "�θ���\n")
		+ (Where.getInterrupt() == 0 ? "" : "�Ŷϸ��ʣ�" + to_string(Where.getInterruptRate()) + "%");

	if (sets.size() != 0)
	{
		for each (auto D2 in sets) if (D2._Equal("?") || D2._Equal("��")) return (string)"���÷�����"
			+ "\n.echo <����>=<ֵ> [<����>=<ֵ>]"
			+ "\n"
			+ "\n�������ԣ�"
			+ "\n����״̬��st/stat������EchoPlayer�Ƿ�����Ӧ�趨Ϊon/off"
			+ "\n����ģʽ��ct/counter�����Ʒ���ģʽ�Ƿ�����Ӧ�趨Ϊon/off"
			+ "\n����������rt/repeat��ָ�����پ������ٴθ�����Żᴥ��EchoPlayer�ĸ�����Ӧ�趨Ϊ��С��0������"
			+ "\n�������ʣ�rr/rtrate��ָ��EchoPlayer�����ĸ��ʣ�Ӧ�趨Ϊ��СΪ0���Ϊ100������"
			+ "\n�Ŷϼ�����it/interrupt��ָ�����پ������ٴθ�����Żᴥ��EchoPlayer���Ŷϣ�Ӧ�趨Ϊ��С��0�������������ģ�"
			+ "\n�Ŷϸ��ʣ�ir/itrate��ָ��EchoPlayer�Ŷϵĸ��ʣ�Ӧ�趨Ϊ��СΪ0���Ϊ100������"
			+ "\n�Ŷ��ı���s1��ָ��EchoPlayer�Ŷϸ���ʱ���õ��ı������趨Ϊ�����ı�"
			+ "\n�����ı���s2��ָ�����Ŷ��ı�������ʱEchoPlayer�����Ŷ����õ��ı������趨Ϊ�����ı������������Ŷ��ı��ظ�"
			+ "\n"
			+ "\nע�����"
			+ "\n����ģʽ��ָ��������������Ϣ�̣ܶ�С��4���ֽڣ�����������Ŷ������룩ʱ��EchoPlayer�ᷢ�͡�xxʲôxx������������ĸ�����"
			+ "\n���ںš�=�����������඼�����пո񣬷���ᵼ���޷�����ʶ���ֶΡ�"
			+ "\n���������봥������֮��Ĺ�ϵΪ���롱����ֻ���ڸ��������ﵽ���������󣬲Żᰴ�մ������ʽ��и������Ŷ�ͬ��"
			+ "\n�����������趨Ϊ0ʱ����ʾ����Ҫ�����������ɴ�������ÿһ����Ϣ���ᰴ�մ������ʴ������������������ʱ���Ϊ100����ÿһ����Ϣ���ᱻ����������"
			+ "\n���Ŷϼ����趨Ϊ0ʱ���ŶϹ��ܻ�رգ�������Ϊ��û���γɸ���ʱ��Ӧ�����Ŷϡ���Ҫʹ���ŶϹ��ܣ��Ŷϼ���Ӧ�����趨Ϊ1��"
			+ "\n�������������Ŷϼ�����������ʱ�����Ƚ����Ŷ��ж������磬�Ŷϸ���Ϊ80%����������Ϊ40%ʱ��ʵ����Ӧ���Ϊ���Ŷ�80%������8%������Ӧ12%��"
			+ "\n"
			+ "\nʾ����"
			+ "\n.echo stat=on"
			+ "\n����EchoPlayer��"
			+ "\n.echo repeat=0 rtrate=20"
			+ "\n���ô�������Ϊ0����������Ϊ20%��ÿ����Ϣ����20%�ļ��ʴ���������"
			+ "\n.echo rt=1 rr=100 it=3 ir=50 ct=on"
			+ "\n��һ����Ϣ������1�κ�100%���ʸ�������������Ϣ������3�κ�EchoPlayer����ĸ���Ҳ�����룩��50%�����Ŷϣ���������ģʽ��";
		
		string key;
		string fail;
		bool edit[8] = { false };
		int val;
		string str;

		for each (auto D2 in sets)
		{
			if (D2.find("=") == string::npos || D2.find("=") == 0)
			{
				fail += "��\n�޷�ʶ���ֶΡ�" + D2 + "��";
				continue;
			}

			key = D2.substr(0, D2.find("="));
			for (auto Fd = key.begin(); Fd != key.end(); Fd++) if ('A' <= *Fd && *Fd <= 'Z')* Fd += 'a' - 'A';

			if (key._Equal("st") || key._Equal("stat"))
			{
				str = D2.substr(D2.find("=") + 1);
				for (auto Fd = str.begin(); Fd != str.end(); Fd++) if ('A' <= *Fd && *Fd <= 'Z')* Fd += 'a' - 'A';
				if (str.empty()) fail += "��\n��ҪΪ����״̬�趨һ��ֵ��on/off��";
				else if (str._Equal("on") || str._Equal("1")) Where.setStat(true), edit[0] = true;
				else if (str._Equal("off") || str._Equal("0")) Where.setStat(false), edit[0] = true;
				else fail += "��\n����״̬Ӧ���趨Ϊon/off";
			}
			else if (key._Equal("ct") || key._Equal("counter"))
			{
				str = D2.substr(D2.find("=") + 1);
				for (auto Fd = str.begin(); Fd != str.end(); Fd++) if ('A' <= *Fd && *Fd <= 'Z')* Fd += 'a' - 'A';
				if (str.empty()) fail += "��\n��ҪΪ����ģʽ�趨һ��ֵ��on/off��";
				else if (str._Equal("on") || str._Equal("1")) Where.setCounter(true), edit[1] = true;
				else if (str._Equal("off") || str._Equal("0")) Where.setCounter(false), edit[1] = true;
				else fail += "��\n����ģʽӦ���趨Ϊon/off";
			}
			else if (key._Equal("rt") || key._Equal("repeat"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "��\n��ҪΪ���������趨һ��ֵ���Ǹ�������";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "��n����������ӦС��0";
					else Where.setRepeat(val), edit[2] = true;
				}
				catch (str_not_num e)
				{
					fail += "��\n��������Ӧ���趨Ϊ�Ǹ�����";
				}
			}
			else if (key._Equal("rtrate") || key._Equal("rr"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "��\n��ҪΪ���������趨һ��ֵ��0-100��";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "��\n�������ʲ�ӦС��0";
					else if (val > 100) fail += "��\n�������ʲ�Ӧ����100";
					else Where.setRepeatRate(val), edit[3] = true;
				}
				catch (str_not_num e)
				{
					fail += "��\n��������Ӧ���趨��СΪ0�����Ϊ100������";
				}
			}
			else if (key._Equal("it") || key._Equal("interrupt"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "��\n��ҪΪ�Ŷϼ����趨һ��ֵ����С��0��������";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "��n�Ŷϼ�����ӦС��0";
					else Where.setInterrupt(val), edit[4] = true;
				}
				catch (str_not_num e)
				{
					fail += "��n�Ŷϼ���Ӧ���趨Ϊ��С��0������";
				}
			}
			else if (key._Equal("itrate") || key._Equal("ir"))
			{
				if (D2.substr(D2.find("=") + 1).empty()) fail += "��\n��ҪΪ�Ŷϸ����趨һ��ֵ��0-100��";
				else try
				{
					val = to_int(D2.substr(D2.find("=") + 1));
					if (val < 0) fail += "��\n�Ŷϸ��ʲ�ӦС��0";
					else if (val > 100) fail += "��\n�Ŷϸ��ʲ�Ӧ����100";
					else Where.setInterruptRate(val), edit[5] = true;
				}
				catch (str_not_num e)
				{
					fail += "��n�Ŷϸ���Ӧ���趨��СΪ0�����Ϊ100������";
				}
			}
			else if (key._Equal("s1"))
			{
				str = D2.substr(D2.find("=") + 1);
				if (str.empty()) fail += "��\n��ҪΪ�Ŷ��ı��趨һ��ֵ�������ı���";
				else Where.setS1(str), edit[6] = true;
			}
			else if (key._Equal("s2"))
			{
				str = D2.substr(D2.find("=") + 1);
				if (str.empty()) fail += "\n��ҪΪ�����ı��趨һ��ֵ�������ı�����";
				else Where.setS2(str), edit[7] = true;
			}
			else fail += "��\nû�д����ԣ�" + key;
		}
		if (!fail.empty()) fail.erase(0, 2), fail += "��";

		if (Where.getS1()._Equal(Where.getS2()))
		{
			edit[7] = true;
			if (!Where.getS1()._Equal("ѧʲôѧ")) Where.setS2("ѧʲôѧ");
			else Where.setS2("��ϸ���");
		}

		for (int i = 0; i != 8; i++) if (edit[i]) switch (i)
		{
		case 0: Ly += (string)"��\nEchoPlayer" + (Where.getStat() ? "����" : "�ر�"); break;
		case 1: Ly += (string)"��\n����ģʽ" + (Where.getCounter() ? "����" : "�ر�"); break;
		case 2: Ly += "��\n���������趨Ϊ" + to_string(Where.getRepeat()); break;
		case 3: Ly += "��\n���������趨Ϊ" + to_string(Where.getRepeatRate()) + "%"; break;
		case 4: Ly += (Where.getInterrupt() == 0 ? "��\n�ŶϹ��ܹر�" : "��\n�Ŷϼ����趨Ϊ" + to_string(Where.getInterrupt())); break;
		case 5: Ly += (Where.getInterrupt() == 0 ? "" : "��\n�Ŷϸ����趨Ϊ" + to_string(Where.getInterruptRate()) + "%"); break;
		case 6: Ly += (Where.getInterrupt() == 0 ? "" : "��\n�Ŷ��ı��趨Ϊ��" + Where.getS1() + "��"); break;
		case 7: Ly += (Where.getInterrupt() == 0 ? "" : "��\n�����ı��趨Ϊ��" + Where.getS2() + "��"); break;
		}
		if (!Ly.empty()) Ly.erase(0, 3), Ly += "��";
		if (!fail.empty()) Ly += fail;
	}

	return Ly;
}



///	����ڵ㡿

//	�����߳���ڵ�
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
					if (cy.size() != 1) sudoStr = (string)"�����������Ѿ��Ӹ����������˽���D20��ע�����"
						+ "\n�ܽ���������������㣺"
						+ "\n"
						+ "\n    #1) ���ر��˵���Ը��"
						+ "\n    #2) ���Ǻú���ͷ��ա�"
						+ "\n    #3) Ȩ��Խ������Խ��"
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
					throw (arg_illegal("-asg��-asd��-asp", "����������ֻ��ͬʱʹ��һ����"));
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
							throw (arg_illegal("(-as)" + *it, "�����Ϊ��ȷ��QQ���룬����ֱ��@��Ա��"));
						asQQ = to_QQNumber(*it);
						args.erase(it--);
						break;
					case 1:
						if (!is_QQNumber(*it))
							throw (arg_illegal("(-asg)" + *it, "�����Ϊ��ȷ��Ⱥ���롣"));
						asinGroup = to_QQNumber(*it);
						args.erase(it--);
						break;
					case 2:
						if (!is_QQNumber(*it))
							throw (arg_illegal("(-asd)" + *it, "�����Ϊ��ȷ������롣"));
						asinGroup = to_QQNumber(*it);
						args.erase(it--);
						break;
					}
					ACP.pop();
				}
			}
		}
		if (as && asQQ == -1)
			throw (arg_not_found("����-as", string("") + "��ָ��QQ����" + (type == PVT ? "" : "������ֱ��@��Ա") + "��"));
		if (asG && asinGroup == -1)
			throw (arg_not_found("����-asg", string("") + "��ָ��Ⱥ���롣"));
		if (asD && asinDiscuss == -1)
			throw (arg_not_found("����-asd", string("") + "��ָ������롣"));

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