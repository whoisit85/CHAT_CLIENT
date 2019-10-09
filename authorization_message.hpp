#pragma once
#ifndef AUTH_MESSAGE_HPP
#define AUTH_MESSAGE_HPP

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

class authorization_message
{
public:
	enum { header_length = 4 };
	enum { max_body_length = 512 };

	authorization_message()
		: body_length_(0), login(""), password(""), mess1(""), mess2 (""), data_("")
	{
	}
	
	authorization_message(std::string login, std::string pass, std::string mess1, std::string mess2)
		: body_length_(0), login(login), password(pass), mess1(mess1), mess2(mess2), data_("")
	{
	}

	const char* data() const
	{
		return data_;
	}

	char* data()
	{
		return data_;
	}

	std::size_t length() const
	{
		return header_length + body_length_;
	}

	const char* body() const
	{
		return data_ + header_length;
	}

	char* body()
	{
		return data_ + header_length;
	}

	std::size_t body_length() const
	{
		return body_length_;
	}

	void body_length(std::size_t new_length)
	{
		body_length_ = new_length;
		if (body_length_ > max_body_length)
			body_length_ = max_body_length;
	}

	bool decode_header()
	{
		char header[header_length + 1] = "";
		strncat_s(header, data_, header_length);
		body_length_ = std::atoi(header);
		if (body_length_ > max_body_length)
		{
			body_length_ = 0;
			return false;
		}
		return true;
	}

	void encode_header()
	{
		std::string payload = "AUTH:";
		payload += login;
		payload += ";";
		payload += password;
		payload += ";";
		payload += mess1;
		payload += ";";
		payload += mess2;
		payload += ";";

		const char* format = "%4d";
		const char* payload1 = payload.data();
		char* payload2 = _strdup(payload1);
		size_t size = sizeof(payload2);
		std::snprintf(payload2, size, format, static_cast<int>(body_length_));
		std::memcpy(data_, payload2, header_length);
	}

private:
	char data_[header_length + max_body_length];
	std::size_t body_length_;
	std::string login;
	std::string password;
	std::string mess1;
	std::string mess2;
};


#endif // AUTH_MESSAGE_HPP
