import std.exception : enforce;
import std.socket : InternetAddress;
import std.sumtype : match, SumType;

///
struct BytePacketBuffer
{
private:
    size_t _pos;

public:
    ubyte[512] _buf;

    ///
    size_t pos() nothrow pure
    {
        return _pos;
    }

    ///
    void step(size_t steps)
    {
        _pos += steps;
    }

    ///
    void seek(size_t pos)
    {
        _pos = pos;
    }

    ///
    ubyte read()
    {
        enforce(_pos < 512, "End of buffer");
        const res = _buf[_pos];
        _pos++;
        return res;
    }

    ///
    ubyte get(size_t pos)
    {
        enforce(pos < 512, "End of buffer");
        return _buf[pos];
    }

    ///
    ubyte[] getRange(size_t start, size_t len)
    {
        enforce(start + len < 512, "End of buffer");
        return _buf[start .. start + len];
    }

    ///
    ushort readU16()
    {
        return (cast(ushort) read() << 8) | read();
    }

    ///
    uint readU32()
    {
        return (cast(uint) read()) << 24 |
            read() << 16 |
            read() << 8 |
            read();
    }

    /// QNAMEフィールドの読み出し
    void readQname(out string s)
    {
        import std.format : format;
        import std.string : toLower;

        auto pos = pos();

        bool jumped = false;
        immutable maxJumps = 5;
        auto jumpsPerformed = 0;

        auto delim = "";

        while (true)
        {
            enforce(jumpsPerformed <= maxJumps, format!"Limit of %d jumps exceeded"(maxJumps));

            // ラベルの先頭は文字数の情報
            auto len = get(pos);

            // メッセージ圧縮が行われている場合
            if ((len & 0xC0) == 0xC0)
            {
                if (!jumped)
                {
                    // バッファの位置: 長さとオフセット情報をスキップ
                    seek(pos + 2);
                }

                // オフセット位置の計算
                ushort b2 = get(pos + 1);
                auto offset = ((len ^ 0xC0) << 8) | b2;
                pos = offset;

                jumped = true;
                jumpsPerformed++;

                continue;
            }
            else
            {
                // 長さのバイトをスキップ
                pos++;

                // 長さ0のラベルなら終了
                if (len == 0)
                    break;

                s ~= delim;

                auto sBuf = getRange(pos, len);
                s ~= (cast(string) sBuf).toLower;

                delim = ".";

                pos += len;
            }
        }

        if (!jumped)
            seek(pos);
    }

	///
	void write(ubyte val)
	{
		enforce(_pos < 512, "End of buffer");
		_buf[_pos] = val;
		_pos++;
	}

	alias write writeU8;

	///
	void writeU16(ushort val)
	{
		write(val >> 8);
		write(val & 0xFF);
	}

	///
	void writeU32(uint val)
	{
		write((val >> 24) & 0xFF);
		write((val >> 16) & 0xFF);
		write((val >> 8) & 0xFF);
		write(val & 0xFF);
	}

	///
	void writeQname(string qname)
	{
		import std.string : representation, split;
		foreach (label; qname.split('.'))
		{
			auto len = label.length;
			enforce(len <= 0x3F, "Single label exceeds 63 characters of length");
			writeU8(cast(ubyte) len);
			foreach (b; label.representation)
			{
				writeU8(b);
			}
		}
		writeU8(0);
	}
}

///
enum ResultCode : ubyte
{
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED
}

///
struct DnsHeader
{
    ushort _id;  // ランダムなID

    bool _recursionDesired;  // 別のサーバへの問い合わせを行ってほしいか
    bool _truncatedMessage;  // 先頭のデータか
    bool _authoritativeAnswer;  // 直接問い合わせをうけたサーバが返したか
    ubyte _opcode;  // 問い合わせの種類
    bool _response;  // クエリーレスポンス: 0=query, 1=response

    ResultCode _rescode;  // レスポンスのステータス
    bool _checkingDisabled;
    bool _authedData;
    bool _z;  // 予約済み(ただしDNSSECで使われてるらしい)
    bool _recursionAvailable;  // 再帰での問い合わせに対応しているか

    ushort _questions;  // 質問の数
    ushort _answers;  // 回答の数
    ushort _authoritativeEntries;  // オーソリティの数
    ushort _resourceEntries;  // 追加情報の数

    ///
    void read(ref BytePacketBuffer buffer)
    {
        _id = buffer.readU16();

        auto flags = buffer.readU16();
        ubyte a = flags >> 8;
        ubyte b = flags & 0xFF;
        _recursionDesired = (a & 1) > 0;
        _truncatedMessage = (a & (1 << 1)) > 0;
        _authoritativeAnswer = (a & (1 << 2)) > 0;
        _opcode = (a >> 3) & 0x0F;
        _response = (a & (1 << 7)) > 0;

        _rescode = cast(ResultCode) (b & 0x0F);
        _checkingDisabled = (b & (1 << 4)) > 0;
        _authedData = (b & (1 << 5)) > 0;
        _z = (b & (1 << 6)) > 0;
        _recursionAvailable = (b & (1 << 7)) > 0;

        _questions = buffer.readU16();
        _answers = buffer.readU16();
        _authoritativeEntries = buffer.readU16();
        _resourceEntries = buffer.readU16();
    }

	///
	void write(ref BytePacketBuffer buffer)
	{
		buffer.writeU16(_id);

		buffer.writeU8(
			_recursionDesired
			| cast(ubyte) (_truncatedMessage << 1)
			| cast(ubyte) (_authoritativeAnswer << 2)
			| cast(ubyte) (_opcode << 3)
			| cast(ubyte) (_response << 7)
		);

		buffer.writeU8(
			_rescode
			| cast(ubyte) (_checkingDisabled << 4)
			| cast(ubyte) (_authedData << 5)
			| cast(ubyte) (_z << 6)
			| cast(ubyte) (_recursionAvailable << 7)
		);

		buffer.writeU16(_questions);
		buffer.writeU16(_answers);
		buffer.writeU16(_authoritativeEntries);
		buffer.writeU16(_resourceEntries);
	}
}

private
{
    struct UnknownQueryType { ushort x; }
    struct AQueryType {}
}

///
alias QueryType = SumType!(UnknownQueryType, AQueryType);

///
ushort toNum(QueryType qt) @nogc nothrow pure
{
    return cast(ushort) qt.match!(
        (UnknownQueryType uqt) => uqt.x,
        (AQueryType) => 1
    );
}

///
QueryType fromNum(ushort num) @nogc nothrow pure
{
    switch (num)
    {
        case 1:
            AQueryType aqt;
            QueryType qt = aqt;
            return qt;
        default:
            auto uqt = UnknownQueryType(num);
            QueryType qt = uqt;
            return qt;
    }
    assert(false);
}

///
struct DnsQuestion
{
private:
    string _name;
    QueryType _qtype;

public:
    ///
    this(string name, QueryType qtype)
    {
        _name = name;
        _qtype = qtype;
    }

    ///
    void read(ref BytePacketBuffer buffer)
    {
        buffer.readQname(_name);
        _qtype = fromNum(buffer.readU16());  // qtype
        cast(void) buffer.readU16();  // class
    }

	///
	void write(ref BytePacketBuffer buffer)
	{
		buffer.writeQname(_name);
		auto typenum = _qtype.toNum();
		buffer.writeU16(typenum);
		buffer.writeU16(1);
	}
}

///
private
{
    ///　不明なレコード
    struct UnknownDnsRecord
    {
        string domain;
        ushort qtype;
        ushort dataLen;
        uint ttl;
    }

    /// 32bitのIPv4アドレスを格納するレコード
    struct ADnsRecord
    {
        string domain;
        InternetAddress addr;
        uint ttl;
    }
}

/// DNSレコードタイプ
alias DnsRecord = SumType!(UnknownDnsRecord, ADnsRecord);

///
DnsRecord readDnsRecord(ref BytePacketBuffer buffer)
{
    string domain;
    buffer.readQname(domain);

    auto qtypeNum = buffer.readU16();
    QueryType qtype = fromNum(qtypeNum);
    cast(void) buffer.readU16();
    auto ttl = buffer.readU32();
    auto dataLen = buffer.readU16();

    return qtype.match!(
        (AQueryType aqt) {
            auto rawAddr = buffer.readU32();
            auto addr = new InternetAddress(rawAddr, InternetAddress.PORT_ANY);
            auto adr = ADnsRecord(domain, addr, ttl);
            DnsRecord dr = adr;
            return dr;
        },
        (UnknownQueryType uqt) {
            buffer.step(dataLen);
            auto udr = UnknownDnsRecord(domain, qtypeNum, dataLen, ttl);
            DnsRecord dr = udr;
            return dr;
        }
    );
}

///
size_t writeDnsRecord(DnsRecord record, ref BytePacketBuffer buffer)
{
	auto start = buffer.pos();
	record.match!(
		(ADnsRecord adr) {
			buffer.writeQname(adr.domain);
			buffer.writeU16(1);  // A record query type.
			buffer.writeU16(1);
			buffer.writeU32(adr.ttl);
			buffer.writeU32(4);

			auto octets = adr.addr.addr;
			buffer.writeU8((octets >> 24) & 0xFF);
			buffer.writeU8((octets >> 16) & 0xFF);
			buffer.writeU8((octets >> 8) & 0xFF);
			buffer.writeU8(octets & 0xFF);
		},
		(UnknownDnsRecord udr) {
			import std.stdio;
			writefln("Skipping record: %s", udr);
		}
	);
	return buffer.pos() - start;
}

///
struct DnsPacket
{
    DnsHeader _header;
    DnsQuestion[] _questions;
    DnsRecord[] _answers;
    DnsRecord[] _authorities;
    DnsRecord[] _resources;

    ///
    this(ref BytePacketBuffer buffer)
    {
        _header.read(buffer);

        foreach (_; 0 .. _header._questions)
        {
            QueryType qtype = UnknownQueryType(0);
            auto question = DnsQuestion("", qtype);
            question.read(buffer);
            _questions ~= question;
        }
        foreach (_; 0 .. _header._answers)
        {         
            _answers ~= readDnsRecord(buffer);
        }
        foreach (_; 0 .. _header._authoritativeEntries)
        {
            _authorities ~= readDnsRecord(buffer);
        }
        foreach (_; 0 .. _header._resourceEntries)
        {
            _resources ~= readDnsRecord(buffer);
        }
    }

	///
	void write(ref BytePacketBuffer buffer)
	{
		_header._questions = cast(ubyte) _questions.length;
		_header._answers = cast(ubyte) _answers.length;
		_header._authoritativeEntries = cast(ubyte) _authorities.length;
		_header._resourceEntries = cast(ubyte) _resources.length;

		_header.write(buffer);

		foreach (question; _questions)
		{
			question.write(buffer);
		}
		foreach (rec; _answers)
		{
			writeDnsRecord(rec, buffer);
		}
		foreach (rec; _authorities)
		{
			writeDnsRecord(rec, buffer);
		}
		foreach (rec; _resources)
		{
			writeDnsRecord(rec, buffer);
		}
	}
}

void main()
{
	import std.socket : UdpSocket;
    import std.stdio;

	auto qname = "google.com";
	AQueryType aqt;
	QueryType qtype = aqt;

	/// google public DNS.
	auto server = new InternetAddress("8.8.8.8", 53);

	///
	auto socket = new UdpSocket;
	auto addr = new InternetAddress("0.0.0.0", 43210);
	socket.bind(addr);

	DnsPacket packet;

	packet._header._id = 6666;
	packet._header._questions = 1;
	packet._header._recursionDesired = true;
	packet._questions ~= DnsQuestion(qname, qtype);

    BytePacketBuffer reqBuffer;
	packet.write(reqBuffer);

	socket.sendTo(reqBuffer._buf[0..reqBuffer.pos()], server);

	BytePacketBuffer resBuffer;
	socket.receiveFrom(resBuffer._buf);

	auto resPacket = DnsPacket(resBuffer);
	writeln(resPacket._header);

    foreach (q; resPacket._questions)
    {
        writeln(q);
    }
    foreach (rec; resPacket._answers)
    {
        writeln(rec);
    }
    foreach (rec; resPacket._authorities)
    {
        writeln(rec);
    }
    foreach (rec; resPacket._resources)
    {
        writeln(rec);
    }
}
