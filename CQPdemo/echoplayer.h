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

#define ISNUM(n) (n >= '0' && n <= '9' || n == '.')

using namespace std;



///	��ȫ�־�̬������

extern int ac;
static string _home_ = "data\\app\\skot\\";
static string usrDir = _home_ + "usr\\";
static string tmpDir = _home_ + "tmp\\";
static string sudoerFile = _home_ + "sudoers.csv";
static string echoFile = _home_ + "usr\\echo.csv";
static string blackFile = _home_ + "blackList.csv";

static int64_t superadmin = 95806902;

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
	if (_access(tmpDir.data(), 00) == -1) _mkdir(tmpDir.data());
}



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
int to_int(string str)
{
	int Ly = 0;
	bool dT = false;

	bool neg = false;
	if (*str.begin() == '-')
	{
		str.erase(0, 1);
		neg = true;
	}

	for (char D2 : str)
	{
		if (dT) continue;
		else if (D2 == '.') dT = true;
		else if (ISNUM(D2)) Ly *= 10, Ly += D2 - '0';
		else return 0;
	}

	if (neg) Ly = -Ly;
	return Ly;
}
//	���ַ���תΪС��
double to_double(string str)
{
	double Ly = 0;
	int Fred = -1;

	bool neg = false;
	if (*str.begin() == '-')
	{
		str.erase(0, 1);
		neg = true;
	}

	for (char D2 : str)
	{
		if (Fred != -1) Fred++;
		if (D2 == '.') Fred++;
		else if (ISNUM(D2)) Ly *= 10, Ly += D2 - '0';
		else return 0.0;
	}
	if (Fred != -1) for (; Fred != 0; Fred--) Ly /= 10;

	if (neg) Ly = -Ly;
	return Ly;
}
//	���ַ���תΪqq������CQ���@��
int64_t to_QQNumber(string str)
{
	if (str.find("[CQ:at,qq=") == 0 && *(str.end() - 1) == ']') str.erase(0, 10), str.erase(str.end() - 1);
	int64_t Ly = 0;
	bool dT = false;

	bool neg = false;
	if (*str.begin() == '-')
	{
		str.erase(0, 1);
		neg = true;
	}

	for (char D2 : str)
	{
		if (dT) continue;
		else if (D2 == '.') dT = true;
		else if (ISNUM(D2)) Ly *= 10, Ly += D2 - '0';
		else return 0;
	}

	if (neg) Ly = -Ly;
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
	bool Ly = true;
	for (char D2 : str) if ((D2 < '0' || D2 > '9') && D2 != '.' && D2 != '-') Ly = false;
	return Ly;
}



///	���ࡿ

//	Ⱥ��
class Group
{
	int64_t gid;
	vector<int64_t> dM;
	bool stat;
	int rate;
	bool counter;
	string CCC;

public:
	Group(int64_t gid)
	{
		this->gid = gid;
		stat = false;
		rate = 10;
		counter = false;

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
				if (cy[0]._Equal("dm")) dM.push_back(to_int(cy[1]));

				if (cy[0]._Equal("echo"))
				{
					Sp = true;
					stat = cy[1]._Equal("on");
					rate = to_int(cy[2]);
					counter = cy[3]._Equal("counter");
				}
				else CCC += "\n" + P2;
			}
			CH.close();
		}
	}
	string toString()
	{
		string Ly;
		Ly += CCC;
		Ly += (string)"\necho," + (stat ? "on" : "off") + "," + to_string(rate) + "," + (counter ? "counter" : "noCounter");
		if (!Ly.empty()) Ly.erase(0, 1);
		return Ly;
	}
	void Save()
	{
		ofstream kx(usrDir + "g" + to_string(gid) + ".csv");
		if (kx.is_open())
		{
			kx << toString();
			kx.close();
		}
	}

	//	set
	void set(bool stat, int rate, bool counter)
	{
		this->stat = stat;
		this->rate = rate;
		this->counter = counter;
	}

	//	get
	void get(bool& stat, int& rate, bool& counter)
	{
		stat = this->stat;
		rate = this->rate;
		counter = this->counter;
	}

	//	is?
	bool is_dm(int64_t qq)
	{
		for (vector<int64_t>::iterator D2 = dM.begin(); D2 != dM.end(); D2++)
			if (*D2 == qq) return true;
		return false;
	}
};



///	��ָ�

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

//	�ݴ����һ��������������Ϣ
string lastEchoMsg(int64_t Group, string msg = "")
{
	string Ly = "";
	bool Sp = false;

	string CH = tmpDir + "echo";
	string CCC = "";
	string P2 = "";

	ifstream in(CH);
	if (in.is_open())
	{
		vector<string> cy;
		for (bool Tron = false; !in.eof(); Tron = false)
		{
			getline(in, P2); if (P2.empty()) continue;
			if (!Sp)
			{
				cy = csv(P2);
				if (cy[0]._Equal(to_string(Group))) Tron = true;
			}
			if (Tron)
			{
				Sp = true;
				if (msg.empty()) Ly = cy[1];
				else cy[1] = to_csv(msg);
				P2.clear();
				P2 = cy[0] + "," + cy[1];
			}
			CCC += "\n" + P2;
		}
	}

	if (!msg.empty())
	{
		if (!Sp) CCC += "\n" + to_string(Group) + "," + to_csv(msg);
		CCC.erase(0, 1);

		ofstream out(CH);
		if (out.is_open())
		{
			out << CCC;
			out.close();
		}
	}

	return Ly;
}
//	��������
void EchoPlayer(int type, int64_t gid, string msg)
{
	if (blackList.contains(0, gid)) return;

	srand(GetTickCount64());

	Group Where = Group(gid);

	bool stat = false;
	int rate = 10;
	bool counter = false;
	Where.get(stat, rate, counter);

	if (!stat) return;
	if (msg._Equal(lastEchoMsg(gid))) return;

	if (rand() % 100 + 1 > rate) return;

	if (counter)
	{
		string tmpMsg = msg;
		vector<string> Fd
		{ 
			"��","��","��","��","��","��","��","��","��","��","��","��","��","��","��","��",
			".",",","!","?","(",")","<",">","[","]","{","}","-","~",";","*","\'","\"" 
		};
		for (auto D2 : Fd) for (; tmpMsg.find(D2) != string::npos; tmpMsg.erase(tmpMsg.find(D2), D2.length()));

		
		if (!tmpMsg.empty() && tmpMsg.length() < 4)
		{
			if (tmpMsg._Equal("��")) tmpMsg = "��";
			else if (tmpMsg._Equal("��")) tmpMsg = "��";
			msg = tmpMsg + "ʲô" + tmpMsg;
		}
	}
	lastEchoMsg(gid, msg);

	PostMsg(type, gid, msg);
}



/// ��ָ�

//	echoָ��
string echo(bool sudo, int type, int64_t qq, int64_t gid, vector<string> args)
{
	string Ly = "";

	Group Where = Group(gid);

	bool help = false;
	bool ver = false;
	bool src = false;
	bool setStat = false;
	bool setRate = false;
	bool setCounter = false;
	bool list = true;

	/*  id = 0  */	bool newStat;
	/*  id = 1  */	int newRate = 0;
	/*  id = 2  */	int newCounter = -1;

	stack<int> ACP;
	ACP.push(0);

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

			else if (args[i]._Equal("-rate")) setRate = true, ACP.push(1);
			else if (args[i]._Equal("-counter")) setCounter = true, ACP.push(2);

			if (setRate && !sudo && !Where.is_dm(qq))
				throw (operator_is_not_dm("-rate����"));
			if (setCounter && !sudo && !Where.is_dm(qq))
				throw (operator_is_not_dm("-counter����"));
		}
		else
		{
			anal(args[i]);
			if (!ACP.empty())
			{
				switch (ACP.top())
				{
				case 0:
					setStat = true;
					if (setStat && !sudo && !Where.is_dm(qq))
						throw (operator_is_not_dm("-counter����"));
					if (args[i]._Equal("on")) newStat = true;
					else if (args[i]._Equal("off")) newStat = false;
					else throw (arg_illegal(args[i], "ֻ��ʹ��on��off��"));
					break;
				case 1:
					if (!is_num(args[i]))
						throw (arg_illegal("(-rate)" + args[i]), "�����Ϊ1-100����������");
					newRate = to_int(args[i]);
					if (newRate < 1 || newRate>100)
						throw (arg_illegal("(-rate)" + args[i], "�������ʲ���С��1���Ҳ��ܴ���100��"));
					break;
				case 2:
					if (args[i]._Equal("on")) newCounter = 1;
					else if (args[i]._Equal("off")) newCounter = 0;
					else throw (arg_illegal("(-counter)" + args[i], "ֻ��ʹ��on��off��"));
					break;
				}
				ACP.pop();
			}
		}
	}

	if (type == PVT) return "����ָ��echoֻ����Ⱥ/����ʹ�á�";
	if (setRate && newRate == 0) throw (arg_not_found("-rate", "��׷��1-100����������"));
	if (setCounter && newCounter == -1) throw (arg_not_found("-counter", "��Ҫָ��on/off��"));

	bool Aur = sudo || Where.is_dm(qq);
	if (help) return string("")
		+ "���÷���\n"
		+ ".echo" + (Aur ? " [on/off]" : "") + "\n" + (Aur ? "������ر�EchoPlayer�����û���ṩ��������" : "") + "��ʾEchoPlayer��ǰ��״̬��\n\n"
		+ "��������\n"
		+ (Aur ? "-rate <����>\n���ô������ʡ�\n\n" : "")
		+ (Aur ? "-counter <on/off>\n������ر�counterģʽ��\n\n" : "")
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
		+ (ver ? "�� ����618A03 (95806902) ��д��\n" : "")
		+ (src ? "Դ�룺https://github.com/Wyrda-La-Darckonit/EchoPlayer-for-Skot.git" : "");

	bool stat = false;
	int rate = 10;
	bool counter = false;
	Where.get(stat, rate, counter);

	if (setStat)
	{
		Where.set(newStat, rate, counter);
		Where.Save();
		Ly += string("") + "EchoPlayer" + (newStat ? "����" : "�ر�") + "��\n";
	}
	if (setRate)
	{
		Where.set(stat, newRate, counter);
		Where.Save();
		Ly += string("") + "EchoPlayer�Ĵ������ʱ���Ϊ" + to_string(newRate) + "%��\n";
	}
	if (setCounter)
	{
		Where.set(stat, rate, newCounter == 1 ? true : false);
		Where.Save();
		Ly += string("") + "EchoPlayer��counterģʽ" + (newCounter == 1 ? "����" : "�ر�") + "��\n";
	}

	Where.get(stat, rate, counter);
	if (list) Ly += string("") + "EchoPlayer��" + (stat ? "����" : "�ر�") + "\n�������ʣ�" + to_string(rate) + "%\ncounterģʽ��" + (counter ? "����" : "�ر�");

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
		for (int i = 1; i != args.size(); i++)
		{
			if (args[i].find("-") == 0)
			{
				if (args[i]._Equal("-as")) args[i].clear(), as = true, ACP.push(0);
				else if (args[i]._Equal("-asg")) args[i].clear(), asG = true, ACP.push(1);
				else if (args[i]._Equal("-asd")) args[i].clear(), asD = true, ACP.push(2);
				else if (args[i]._Equal("-asp")) args[i].clear(), asP = true;

				if (asG && asD || asG && asP || asD && asP)
					throw (arg_illegal("-asg��-asd��-asp", "����������ֻ��ͬʱʹ��һ����"));
			}
			else
			{
				if (!ACP.empty())
				{
					anal(args[i]);
					switch (ACP.top())
					{
					case 0:
						if (!is_QQNumber(args[i]))
							throw (arg_illegal("(-as)" + args[i], "�����Ϊ��ȷ��QQ���룬����ֱ��@��Ա��"));
						asQQ = to_QQNumber(args[i]);
						args[i].clear();
						break;
					case 1:
						if (!is_QQNumber(args[i]))
							throw (arg_illegal("(-asg)" + args[i], "�����Ϊ��ȷ��Ⱥ���롣"));
						asinGroup = to_QQNumber(args[i]);
						args[i].clear();
						break;
					case 2:
						if (!is_QQNumber(args[i]))
							throw (arg_illegal("(-asd)" + args[i], "�����Ϊ��ȷ������롣"));
						asinGroup = to_QQNumber(args[i]);
						args[i].clear();
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
		if (args.back()._Equal("--debug"))
		{
			Ly += "type = ";
			switch (type)
			{
			case PVT: Ly += "private\n"; break;
			case GRP: Ly += "group\n"; break;
			case DIS: Ly += "discuss\n"; break;
			}
			Ly += "QQ = " + to_string(qq) + "\n";
			if (type != PVT) Ly += "Group = " + to_string(gid) + "\n";
			Ly += "argc = " + to_string(args.size() - 1);
			for (int i = 0; i != args.size() - 1; i++)
			{
				Ly.append("\nargv[").append(to_string(i)).append("] = ").append(args[i]);
			}
			PostMsg(type, (type == PVT ? qq : gid), Ly);
			return;
		}
		else if (args[0]._Equal("echo")) Ly += echo(sudo, type, qq, gid, args);
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