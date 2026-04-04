/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2026 Richard Kojedzinszky
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cam/scsi/scsi_all.h>
#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_ioctl.h>

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "ctld.hh"
#include "control.hh"

struct arg {
	std::string_view name;
	std::string value;
};

struct client {
	int fd;
	char rbuf[16384];

	client(int fd_) : fd(fd_) { rbuf[0] = 0; }

	void do_read(struct conf &config);
	void do_write(const char *fmt, ...);
	void close();

private:
	void auth_group_set(struct conf &config, std::string_view id, const std::vector<arg> &args);
	void auth_group_del(struct conf &config, std::string_view id, const std::vector<arg> &args);
	void lun_set(struct conf &config, std::string_view id, const std::vector<arg> &args);
	void lun_del(struct conf &config, std::string_view id, const std::vector<arg> &args);
	void target_add(struct conf &config, std::string_view id, const std::vector<arg> &args);
	void target_set_lun(struct conf &config, std::string_view id, const std::vector<arg> &args);
	void target_del(struct conf &config, std::string_view id, const std::vector<arg> &args);

	using command_func = void (client::*)(struct conf &, std::string_view, const std::vector<arg> &);
	static const std::map<std::string, command_func>& get_commands();
};

static std::map<int, std::unique_ptr<client>> clients;
static int control_fd = -1;
static struct sockaddr_un addr;
static int kqfd_control = -1;

static void client_new(int fd);

const std::map<std::string, client::command_func>& client::get_commands() {
	static const std::map<std::string, command_func> commands = {
		{"auth-group-set", &client::auth_group_set},
		{"auth-group-del", &client::auth_group_del},
		{"lun-set", &client::lun_set},
		{"lun-del", &client::lun_del},
		{"target-add", &client::target_add},
		{"target-set-lun", &client::target_set_lun},
		{"target-del", &client::target_del},
	};
	return commands;
}

static std::string unquote(std::string_view src);
static std::vector<std::string_view> split(std::string_view str, char delim);

int
control_init(const char *sock, int kqfd)
{
	struct kevent kev;

	memset(&addr, 0, sizeof(addr));
	addr.sun_len = sizeof(addr);
	addr.sun_family = AF_UNIX;

	kqfd_control = kqfd;
	control_fd = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	if (control_fd == -1)
		return (-1);

	strlcpy(addr.sun_path, sock, sizeof(addr.sun_path));

	if (bind(control_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(control_fd);
		control_fd = -1;
		return (-1);
	}

	if (listen(control_fd, 10) == -1) {
		close(control_fd);
		control_fd = -1;
		return (-1);
	}

	EV_SET(&kev, control_fd, EVFILT_READ, EV_ADD, 0, 0, nullptr);
	if (kevent(kqfd, &kev, 1, NULL, 0, NULL) == -1) {
		close(control_fd);
		control_fd = -1;
		return (-1);
	}

	return (0);
}

void
control_shutdown(void)
{
	if (control_fd >= 0) {
		close(control_fd);
		control_fd = -1;
		unlink(addr.sun_path);
	}

	clients.clear();
}

void
control_postfork(void)
{
	for (auto &kv : clients)
		::close(kv.second->fd);
	clients.clear();

	if (control_fd >= 0) {
		::close(control_fd);
		control_fd = -1;
	}
}

void
control_handle_kqueue(struct conf &config, struct kevent *kev)
{
	if (control_fd == -1)
		return;

	// All events we are listening for are READ events
	if (kev->filter != EVFILT_READ)
		return;

	if ((int)kev->ident == control_fd) {
		struct sockaddr_un cl_addr;
		socklen_t cl_addr_len = sizeof(cl_addr);
		int clfd;

		clfd = accept(control_fd, (struct sockaddr *)&cl_addr,
		    &cl_addr_len);
		if (clfd >= 0)
			client_new(clfd);
		return;
	}

	auto it = clients.find(kev->ident);
	if (it != clients.end()) {
		it->second->do_read(config);
	}
}

static void
client_new(int fd)
{
	struct kevent kev;
	auto cl = std::make_unique<client>(fd);

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, nullptr);
	if (kevent(kqfd_control, &kev, 1, NULL, 0, NULL) == -1) {
		log_warn("kevent");
		close(fd);
		return;
	}
	clients[fd] = std::move(cl);
}

void
client::close()
{
	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
	kevent(kqfd_control, &kev, 1, NULL, 0, NULL);

	::close(fd);
	clients.erase(fd);
}

static std::vector<std::string_view> split(std::string_view str, char delim)
{
	std::vector<std::string_view> tokens;
	size_t start = 0;
	size_t end = str.find(delim);

	while (end != std::string_view::npos) {
		tokens.push_back(str.substr(start, end - start));
		start = end + 1;
		end = str.find(delim, start);
	}

	if (start < str.length())
		tokens.push_back(str.substr(start));

	return tokens;
}

void
client::do_read(struct conf &config)
{
	int len = read(fd, rbuf, sizeof(rbuf) - 1);
	if (len <= 0) {
		close();
		return;
	}

	rbuf[len] = '\0';
	std::string_view input(rbuf, len);

	while (!input.empty() && (input.back() == '\n' || input.back() == '\r'))
		input.remove_suffix(1);

	auto tokens = split(input, ' ');
	if (tokens.empty()) {
		do_write("EMPTY COMMAND");
		return;
	}

	std::string_view cmd = tokens[0];
	std::string id;
	if (tokens.size() > 1)
		id = unquote(tokens[1]);

	const auto& commands = get_commands();
	auto it = commands.find(std::string(cmd));
	if (it == commands.end()) {
		do_write("UNKNOWN COMMAND");
		return;
	}

	std::vector<arg> args;
	for (size_t i = 2; i < tokens.size(); i++) {
		auto eq_pos = tokens[i].find('=');
		if (eq_pos != std::string_view::npos) {
			arg a;
			a.name = tokens[i].substr(0, eq_pos);
			a.value = unquote(tokens[i].substr(eq_pos + 1));
			args.push_back(std::move(a));
		} else {
			arg a;
			a.name = tokens[i];
			a.value = "";
			args.push_back(std::move(a));
		}
	}

	(this->*(it->second))(config, id, args);
}

void
client::do_write(const char *fmt, ...)
{
	char buf[1024];
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	strcat(buf + len, "\n");
	len += 1;

	if (send(fd, buf, len, MSG_NOSIGNAL) != len)
		close();
}

void
client::auth_group_set(struct conf &config, std::string_view id,
    const std::vector<arg> &args)
{
	static const char *help = "Usage: <id> [type[=none|deny|chap|chap-mutual]] [auth[=user:secret[:user2:secret2]]]...";
	struct auth_group *ag;

	if (id.empty()) {
		do_write(help);
		return;
	}

	if (id == "default") {
		do_write("ERR: cannot update default");
		return;
	}

	ag = config.add_auth_group(std::string(id).c_str());
	if (ag == NULL) {
		auto ag_sp = config.find_auth_group(id);
		if (!ag_sp) {
			do_write("ERR: cannot create auth-group");
			return;
		}
		ag = ag_sp.get();
	}

	for (const auto &arg : args) {
		if (arg.name == "type") {
			if (!arg.value.empty()) {
				ag->control_reset();
				if (!ag->set_type(arg.value.c_str())) {
					do_write(
					    "Failed to set auth-type to %s",
					    arg.value.c_str());
					return;
				}
			}
		} else if (arg.name == "auth") {
			if (!arg.value.empty()) {
				auto parts = split(arg.value, ':');

				if (parts.size() < 2) {
					do_write(
					    "AG %s: invalid auth, incomplete",
					    std::string(id).c_str());
					return;
				}

				std::string user_uq = unquote(parts[0]);
				std::string secret_uq = unquote(parts[1]);
				std::string user2_uq = parts.size() > 2 ? unquote(parts[2]) : "";
				std::string secret2_uq = parts.size() > 3 ? unquote(parts[3]) : "";

				bool success;
				if (user2_uq.empty() || secret2_uq.empty()) {
					success = ag->add_chap(user_uq.c_str(),
					    secret_uq.c_str());
				} else {
					success = ag->add_chap_mutual(user_uq.c_str(),
					    secret_uq.c_str(), user2_uq.c_str(), secret2_uq.c_str());
				}

				if (!success) {
					do_write(
					    "Failed to add auth");
					return;
				}
			}
		} else {
			do_write("UNKNOWN_ARG");
			return;
		}
	}

	do_write("OK");
}

void
client::auth_group_del(struct conf &config, std::string_view id,
    const std::vector<arg> &args)
{
	static const char *help = "Usage: <id>";
	(void)args;

	if (id.empty()) {
		do_write(help);
		return;
	}

	if (id == "default") {
		do_write("ERR: cannot delete default");
		return;
	}

	auto ok = config.control_del_auth_group(id);
	if (!ok) {
		do_write("OK - not found");
		return;
	}

	do_write("OK");
}

void
client::lun_set(struct conf &config, std::string_view id,
    const std::vector<arg> &args)
{
	static const char *help = "Usage: <id> [backend[=block|ramdisk]] [blocksize[=size]] [ctl-lun=lun_id] [device-id[=string]] [device-type[=type]] [option=name[=val]] [path=path] [serial[=string]] [size[=size]]";

	if (id.empty()) {
		do_write(help);
		return;
	}

	struct lun newlun(&config, id);
	for (const auto &arg : args) {
		if (arg.name == "backend") {
			if (!newlun.set_backend(arg.value)) {
				do_write(
				    "ERR: backend: invalid value");
				return;
			}
		} else if (arg.name == "blocksize") {
			if (!newlun.set_blocksize(std::stoul(arg.value))) {
				do_write(
				    "ERR: blocksize: invalid value");
				return;
			}
		} else if (arg.name == "ctl-lun") {
			if (!newlun.set_ctl_lun(std::stoul(arg.value))) {
				do_write(
				    "ERR: ctl-lun: invalid value");
				return;
			}
		} else if (arg.name == "device-id") {
			if (!newlun.set_device_id(arg.value)) {
				do_write(
				    "ERR: device-id: invalid value");
				return;
			}
		} else if (arg.name == "device-type") {
			if (!arg.value.empty()) {
				if (!newlun.set_device_type(arg.value.c_str())) {
					do_write(
					    "ERR: device-type: invalid value");
					return;
				}
			}
		} else if (arg.name == "option") {
			auto eq_pos = arg.value.find('=');
			if (eq_pos == std::string::npos) {
				do_write(
				    "ERR: must specify option name");
				return;
			}

			std::string opname(arg.value.substr(0, eq_pos));
			std::string value_uq = unquote(arg.value.substr(eq_pos + 1));
			if (!value_uq.empty()) {
				if (!newlun.add_option(opname.c_str(), value_uq.c_str())) {
					do_write(
					    "ERR: option: invalid value");
					return;
				}
			}
		} else if (arg.name == "path") {
			if (!newlun.set_path(arg.value)) {
				do_write(
				    "ERR: path: invalid value");
				return;
			}
		} else if (arg.name == "serial") {
			if (!newlun.set_serial(arg.value)) {
				do_write(
				    "ERR: serial: invalid value");
				return;
			}
		} else if (arg.name == "size") {
			if (!newlun.set_size(std::stoull(arg.value))) {
				do_write(
				    "ERR: size: invalid value");
				return;
			}
		} else {
			do_write("ERR: unknown arg: %s", std::string(arg.name).c_str());
			return;
		}
	}

	if (!newlun.verify()) {
		do_write("ERR: lun verification failed");
		return;
	}

	struct lun *lun = config.find_lun(id);
	bool update{false};
	if (lun != nullptr) {
		// If ctl-lun is not specified, keep the old one
		if (newlun.ctl_lun() == -1) {
			newlun.set_ctl_lun(lun->ctl_lun());
		}

		if (newlun.ctl_lun() != lun->ctl_lun() || newlun.changed(*lun)) {
			lun->kernel_remove();
		} else {
			update = true;
		}
	} else {
		lun = config.add_lun(std::string(id).c_str());
		if (lun == nullptr) {
			do_write("ERR: failed to add lun");
			return;
		}
	}
	*lun = std::move(newlun);

	if (update) {
		lun->kernel_modify();
	} else {
		lun->kernel_add();
	}

	do_write("OK");
}

void
client::lun_del(struct conf &config, std::string_view id,
    const std::vector<arg> &args)
{
	static const char *help = "Usage: <id>";
	struct lun *lun;
	(void)args;

	if (id.empty()) {
		do_write(help);
		return;
	}

	lun = config.find_lun(std::string(id).c_str());
	if (lun == NULL) {
		do_write("OK - not found");
		return;
	}

	lun->kernel_remove();
	config.delete_target_luns(lun);
	config.control_del_lun(id);

	do_write("OK");
}

void
client::target_add(struct conf &config, std::string_view id,
    const std::vector<arg> &args)
{
	static const char *help = "Usage: <id> [alias[=text]] [auth-group=name] [portal-group=pgname[:agname]]";
	struct target *tgt;

	if (id.empty()) {
		do_write(help);
		return;
	}

	std::string id_str(id);
	tgt = config.add_target(id_str.c_str());
	if (tgt == NULL) {
		do_write(
		    "ERR: error creating target: wrong name or target already exists");
		return;
	}

	for (const auto &arg : args) {
		if (arg.name == "alias") {
			if (!arg.value.empty())
				tgt->set_alias(arg.value.c_str());
		} else if (arg.name == "auth-group") {
			if (arg.value.empty()) {
				do_write(
				    "ERR: must specify auth-group");
				return;
			}

			std::string agname = unquote(arg.value);
			if (!tgt->set_auth_group(agname.c_str())) {
				do_write("ERR: unknown auth-group");
				return;
			}
		} else if (arg.name == "portal-group") {
			if (arg.value.empty()) {
				do_write(
				    "ERR: must specify portal-group");
				return;
			}

			auto parts = split(arg.value, ':');
			std::string pgname_uq = unquote(parts[0]);
			std::string agname_uq;
			const char *agname_cstr = nullptr;
			if (parts.size() > 1) {
				agname_uq = unquote(parts[1]);
				agname_cstr = agname_uq.c_str();
			}

			if (!tgt->add_portal_group(pgname_uq.c_str(),
			    agname_cstr)) {
				do_write(
				    "ERR: failed to add portal-group");
				return;
			}
		} else {
			do_write("UNKNOWN_ARG");
			return;
		}
	}

	if (tgt->auth_group() == nullptr) {
		tgt->set_auth_group("default");
	}

	if (tgt->ports().empty()) {
		tgt->add_portal_group("default", nullptr);
	}

	for (auto *port : tgt->ports()) {
		port->kernel_add();
	}

	do_write("OK");
}

void
client::target_set_lun(struct conf &config, std::string_view id,
    const std::vector<arg> &args)
{
	static const char *help = "Usage: <id> [lunX=vol]...";
	struct target *tgt;

	if (id.empty()) {
		do_write(help);
		return;
	}

	std::string id_str(id);
	tgt = config.find_target(id_str.c_str());
	if (tgt == NULL) {
		do_write("ERR: target not found");
		return;
	}

	for (const auto &arg : args) {
		if (arg.name.compare(0, 3, "lun") == 0) {
			struct lun *lun;

			int idx = std::stoi(std::string(arg.name.substr(3)));
			if (idx < 0 || idx > MAX_LUNS - 1) {
				do_write("ERR: invalid lun index");
				return;
			}

			if (!arg.value.empty()) {
				std::string lunname = unquote(arg.value);
				lun = config.find_lun(lunname.c_str());

				if (lun == NULL) {
					do_write(
					    "ERR: lun not found: %s",
					    arg.value.c_str());
					return;
				}
			} else {
				lun = NULL;
			}

			tgt->control_set_lun(idx, lun);

			for (auto *port : tgt->ports()) {
				struct ctl_lun_map lm;

				const portal_group_port *pgport =
				    dynamic_cast<const portal_group_port *>(port);
				if (pgport == nullptr)
					continue;

				lm.port = pgport->ctl_port();
				lm.plun = idx;

				if (lun == NULL)
					lm.lun = UINT32_MAX;
				else
					lm.lun = lun->ctl_lun();

				if (ioctl(ctl_fd, CTL_LUN_MAP, &lm) != 0)
					log_warn("CTL_LUN_MAP ioctl failed");
			}
		}
	}

	do_write("OK");
}

void
client::target_del(struct conf &config, std::string_view id,
    const std::vector<arg> &args)
{
	static const char *help = "Usage: <id>";
	struct target *tgt;
	(void)args;

	if (id.empty()) {
		do_write(help);
		return;
	}

	tgt = config.find_target(id);
	if (tgt == NULL) {
		do_write("OK - not found");
		return;
	}

	for (auto *port : tgt->ports()) {
		port->kernel_remove();
		config.control_del_port(tgt, port->portal_group());
	}

	config.control_del_target(id);

	do_write("OK");
}

static inline char
nibble(char ch)
{
	switch (ch) {
	case '0' ... '9':
		return (ch - '0');
	case 'a' ... 'f':
		return (ch - 'a' + 10);
	case 'A' ... 'F':
		return (ch - 'A' + 10);
	}

	return (0);
}

static std::string
unquote(std::string_view src)
{
	if (src.empty())
		return "";

	std::string dst;
	dst.reserve(src.length());

	for (size_t i = 0; i < src.length(); i++) {
		char ch = src[i];

		if (ch == '%' && i + 2 < src.length()) {
			ch = (nibble(src[i + 1]) << 4) | nibble(src[i + 2]);
			i += 2;
		}

		dst.push_back(ch);
	}

	return dst;
}

// Additional methods defined in ctld.hh that require control-specific logic are implemented here.

// This method is called when the control interface needs to reset the state of an auth group
void auth_group::control_reset()
{
	ag_type = auth_type::UNKNOWN;
	ag_auths.clear();
	ag_host_names.clear();
	ag_host_addresses.clear();
	ag_initiator_names.clear();
	ag_initiator_portals.clear();
}

bool conf::control_del_auth_group(std::string_view ag_name)
{
	auto it = conf_auth_groups.find(std::string(ag_name));
	if (it == conf_auth_groups.end())
		return false;

	auto ag = it->second.get();

	// reset targets' auth group to default if it matches the one being deleted
	for (auto &tgt : conf_targets) {
		if (tgt.second->auth_group() == ag) {
			tgt.second->control_reset_auth();
		}
	}

	// reset ports' auth group to default if it matches the one being deleted
	for (auto &port : conf_ports) {
		if (port.second->auth_group() == ag) {
			port.second->control_reset_auth_group();
		}
	}

	// reset portal groups' discovery auth group to default if it matches the one being deleted
	for (auto &pg : conf_portal_groups) {
		if (pg.second->discovery_auth_group() == ag) {
			pg.second->control_reset_discovery_auth_group();
		}
	}

	// reset transport groups' discovery auth group to default if it matches the one being deleted
	for (auto &tg : conf_transport_groups) {
		if (tg.second->discovery_auth_group() == ag) {
			tg.second->control_reset_discovery_auth_group();
		}
	}

	conf_auth_groups.erase(it);

	return true;
}

void target::control_reset_auth()
{
	t_private_auth = false;
	t_auth_group = t_conf->find_auth_group("default");
}

void portal_group::control_reset_discovery_auth_group()
{
	pg_discovery_auth_group = pg_conf->find_auth_group("default");
}

void conf::control_del_lun(std::string_view lun_name)
{
	conf_luns.erase(std::string(lun_name));
}

void target::control_set_lun(int idx, struct lun *lun)
{
	if (idx < 0 || idx > MAX_LUNS - 1) {
		return;
	}

	t_luns[idx] = lun;
}

void conf::control_del_target(std::string_view target_name)
{
	conf_targets.erase(std::string(target_name));
}

void conf::control_del_port(struct target *target, struct portal_group *pg)
{
	std::string name = freebsd::stringf("%s-%s", pg->name(),
	    target->name());
	auto it = conf_ports.find(name);
	if (it == conf_ports.end()) {
		return;
	}

	pg->control_remove_port(target);
	conf_ports.erase(it);
}

void portal_group::control_remove_port(struct target *target)
{
	pg_ports.erase(target->name());
}
