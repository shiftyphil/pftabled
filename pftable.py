import ipaddress
from ctypes import Structure, Union, addressof, byref, memmove, pointer, sizeof
from ctypes import c_char, c_int, c_uint8, c_uint32, c_uint16, c_void_p, c_char_p
from socket import AF_INET, AF_INET6
from fcntl import ioctl
from threading import Lock
from typing import List

IOCPARM_MASK = 0x1fff
IOC_VOID = 0x20000000
IOC_OUT = 0x40000000
IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT

PATH_MAX = 1024  # From /usr/include/sys/syslimits.h
PF_TABLE_NAME_SIZE = 32  # From /usr/include/net/pfvar.h
IFNAMSIZ = 16  # From /usr/include/net/if.h
PFRKE_PLAIN = 0


def _IOC(inout, group, num, len):
    return inout | ((len & IOCPARM_MASK) << 16) | (group << 8) | num


def _IOWR(group, num, type):
    return _IOC(IOC_INOUT, ord(group), num, sizeof(type))


class pfr_addr(Structure):  # From /usr/include/net/pfvar.h
    class _pfra_u(Union):
        _fields_ = [("pfra_ip4addr", c_uint32),  # struct in_addr
                    ("pfra_ip6addr", c_uint32 * 4)]  # struct in6_addr

    _anonymous_ = ("pfra_u",)
    _fields_ = [("pfra_u", _pfra_u),
                ("pfra_ifname", c_char * IFNAMSIZ),
                ("pfra_states", c_uint32),
                ("pfra_weight", c_uint16),
                ("pfra_af", c_uint8),
                ("pfra_net", c_uint8),
                ("pfra_not", c_uint8),
                ("pfra_fback", c_uint8),
                ("pfra_type", c_uint8),
                ("pad", c_uint8 * 7)]


class pfr_table(Structure):  # From /usr/include/net/pfvar.h
    _fields_ = [("pfrt_anchor", c_char * PATH_MAX),
                ("pfrt_name", c_char * PF_TABLE_NAME_SIZE),
                ("pfrt_flags", c_uint32),
                ("pfrt_fback", c_uint8)]


class pfioc_table(Structure):  # From /usr/include/net/pfvar.h
    _fields_ = [("pfrio_table", pfr_table),
                ("pfrio_buffer", c_void_p),
                ("pfrio_esize", c_int),
                ("pfrio_size", c_int),
                ("pfrio_size2", c_int),
                ("pfrio_nadd", c_int),
                ("pfrio_ndel", c_int),
                ("pfrio_nchange", c_int),
                ("pfrio_flags", c_int),
                ("pfrio_ticket", c_uint32)]


DIOCRSETADDRS = _IOWR('D', 69, pfioc_table)
DIOCRGETADDRS = _IOWR('D', 70, pfioc_table)


class PFTableAddr:
    """Represents an address in a PF table."""

    def __init__(self, address: str | pfr_addr):
        if isinstance(address, pfr_addr):
            self._from_struct(address)
        elif isinstance(address, str):
            self._from_string(address)
        else:
            raise TypeError("String or pfr_addr expected")

    def __repr__(self):
        return self.to_string()

    def __eq__(self, other):
        return (isinstance(other, PFTableAddr)
                and self.address == other.address
                and self.negate == other.negate)

    def __hash__(self):
        return hash(self.address)

    def _from_string(self, a: str):
        """Initialize a new instance from a string."""
        a = a.strip()
        self.address = ipaddress.ip_network(a.lstrip("!").lstrip(), False)
        self.negate = a.startswith("!")

    def _from_struct(self, a: pfr_addr):
        """Initialize a new instance from a pfr_addr structure."""
        address_length = {AF_INET6: 16, AF_INET: 4}[a.pfra_af]
        address = ipaddress.ip_address(bytes(a.pfra_u)[:address_length])

        self.address = ipaddress.ip_network((address, a.pfra_net))
        self.negate = bool(a.pfra_not)

    def to_string(self):
        """Return the string representation of the address."""
        s = f"{self.address.network_address}"
        if self.address.prefixlen != self.address.max_prefixlen:
            s = f"{s}/{self.address.prefixlen}"
        if self.negate:
            s = f"! {s}"

        return s

    def to_struct(self):
        """Convert this instance to a pfr_addr structure."""
        a = pfr_addr()

        addr = self.address.network_address.packed
        memmove(byref(a.pfra_u), c_char_p(addr), len(addr))

        a.pfra_af = {4: AF_INET, 6: AF_INET6}[self.address.version]
        a.pfra_net = self.address.prefixlen
        a.pfra_not = int(self.negate)
        a.pfra_fback = 0
        a.pfra_type = PFRKE_PLAIN
        a.pfra_ifname = "".encode()

        return a


class PfTable:
    def __init__(self, table_name: str):
        self._pf_dev = open('/dev/pf', 'w')
        self._table_name = table_name
        self._addresses = set(self._get_addresses())
        self._lock = Lock()

    def __del__(self):
        try:
            self._pf_dev.close()
        except AttributeError:
            pass

    def _get_addresses(self, buf_size=20):
        """Get the addresses in the table."""
        table = pfr_table(pfrt_name=self._table_name.encode())

        io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr))

        while True:
            buffer = (pfr_addr * buf_size)()
            io.pfrio_buffer = addressof(buffer)
            io.pfrio_size = buf_size

            ioctl(self._pf_dev, DIOCRGETADDRS, io)

            if io.pfrio_size <= buf_size:
                break
            buf_size = io.pfrio_size

        return [PFTableAddr(a) for a in buffer[:io.pfrio_size]]

    def _set_addresses(self):
        """Update pf from our address list."""
        table = pfr_table(pfrt_name=self._table_name.encode())

        io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr),
                         pfrio_size=len(self._addresses))

        buffer = (pfr_addr * len(self._addresses))(*[a.to_struct() for a in self._addresses])
        io.pfrio_buffer = addressof(buffer)

        ioctl(self._pf_dev, DIOCRSETADDRS, io)

        return io.pfrio_ndel, io.pfrio_nadd, io.pfrio_nchange

    def add(self, address: str):
        """Add address to the table."""
        added = 0
        _address = PFTableAddr(address)
        with self._lock:
            if _address not in self._addresses:
                self._addresses.add(_address)
                (deleted, added, changed) = self._set_addresses()

        return added

    def remove(self, address: str):
        """Delete address from the specified table."""
        deleted = 0
        _address = PFTableAddr(address)
        with self._lock:
            if _address in self._addresses:
                self._addresses.remove(_address)
                (deleted, added, changed) = self._set_addresses()

        return deleted

    def list(self) -> List[str]:
        with self._lock:
            return [a.to_string() for a in self._addresses]

    def clear(self):
        with self._lock:
            self._addresses.clear()
            (deleted, added, changed) = self._set_addresses()

        return deleted
