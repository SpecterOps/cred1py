from lib import socks


def test_init():
    client = socks.SOCKS5Client("cobaltstrike", 9090)
    assert client.proxy_host == "cobaltstrike"
    assert client.proxy_port == 9090

def test_is_ip():
    client = socks.SOCKS5Client("cobaltstrike", 9090)
    assert client._is_ip("192.168.1.2") == True
    assert client._is_ip("127.0.0.1") == True
    assert client._is_ip("localhost") == False
    assert client._is_ip("google.com") == False
    assert client._is_ip("sub.dom.this.com") == False
    
def test_is_domain():
    client = socks.SOCKS5Client("cobaltstrike", 9090)
    assert client._is_domain("www.google.com")
    assert client._is_domain("localhost")
    assert client._is_domain("google.com")
    assert client._is_domain("sub.dom.this.com")
    assert not client._is_domain("192.168.1.1")
    assert not client._is_domain("127.0.0.1")
    
def test_connect_no_auth(mocker):
    client = socks.SOCKS5Client("cobaltstrike", 9090)
    
    mock_response_no_auth = b'\x05\x00\x00\x01\x01\x01\x01\x01\x12\x34'
    mock_response_auth = b'\x05\x01'
    
    mocker.patch("socket.socket.connect")
    mocker.patch("socket.socket.send")
    mocker.patch("socket.socket.recv", return_value=mock_response_no_auth)
    
    client.connect()

def test_connect_error_auth_required(mocker):
    client = socks.SOCKS5Client("cobaltstrike", 9090)
    
    mock_response_auth_required_gssapi = b'\x05\x01'
    mock_response_auth_required_username_password = b'\x05\x02'
    
    mocker.patch("socket.socket.connect")
    mocker.patch("socket.socket.send")
    mocker.patch("socket.socket.recv", return_value=mock_response_auth_required_username_password)
    
    # Verify that an exception is raised
    try:
        client.connect()
        assert False
    except socks.SOCKS5ClientException as e:
        assert str(e) == "Error connecting to proxy: Proxy requires authentication"
    