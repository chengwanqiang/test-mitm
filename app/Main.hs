module Main where

import Network.Socket
import Network.Socket.ByteString as BS
import Foreign
import Foreign.C
import Network.Socket.Internal
import Control.Monad
import qualified Data.ByteString as DBS
import Control.Concurrent
import GHC.IO.Handle
import System.Posix.IO
import System.Posix.Types
import Analysis
import System.Environment

-- Parse the sockaddr structure that is used by the C sockets API into its Haskell
-- SockAddr equivalent. These functions are probably already implemented inside
-- Network.Socket but, alas, are hidden.

parseSockAddrUnix :: Ptr a -> IO SockAddr

parseSockAddrUnix ptr = do
  path <- peekCString (plusPtr ptr 2) --peekCString :: 将以NUL结尾的C字符串封送为Haskell字符串。plusPtr :: 按给定偏移量(以字节为单位)前进给定地址。
  return $ SockAddrUnix path

parseSockAddrInet :: Ptr a -> IO SockAddr

parseSockAddrInet ptr = do
  port <- peekByteOff ptr 2 --从基址和偏移量给出的内存位置读取值。
  addr <- peekByteOff ptr 4
  putStrLn $ show port
  putStrLn $ show addr
  return $ SockAddrInet port addr --SockAddrs 套接字地址。

parseSockAddrInet6 :: Ptr a -> IO SockAddr

parseSockAddrInet6 ptr = do
  port <- peekByteOff ptr 2
  flowInfo <- peekByteOff ptr 4
  addr0 <- peekByteOff ptr 8
  addr1 <- peekByteOff ptr 12
  addr2 <- peekByteOff ptr 16
  addr3<- peekByteOff ptr 20
  scopeId <- peekByteOff ptr 24
  print "=================================================================================================================="
  return $ SockAddrInet6 port flowInfo (addr0, addr1, addr2, addr3) scopeId


-- Must change ccall to stdcall for i386. getsockopt is defined in the object files linked
-- in by the Network package.

foreign import ccall unsafe "getsockopt"
  c_getsockopt :: CInt -> CInt -> CInt -> Ptr a -> Ptr CInt -> IO CInt

-- Gets the original socket address. This is needed because iptables overrides packet
-- headers (including destination address and port) when doing REDIRECTions. A TPROXY
-- target is not viable because it only works on the PREROUTING chain, whereas output from
-- the emulator is on the OUTPUT chain.

getSockOrigDest :: Socket -> IO SockAddr

getSockOrigDest s = do
  let szInt = 128 :: Int -- Size of struct sockaddr_storage
      szCInt = 128 :: CInt -- Size of struct sockaddr_storage
      solIP = 0 -- Protocol level required for SO_ORIGINAL_DST
      soOrigDest = 80 -- The option name SO_ORIGINAL_DST has value 80
      familyOffset = 0 -- Offset of sin_family member of sockaddr_in
  allocaBytes szInt $ \ptr -> do --allocaBytes :: 将指针作为参数传递给临时分配的n个字节的内存块
    withFdSocket s $ \fd -> with szCInt $ \ptr_sz -> do --withFdSocket :: 从套接字获取文件描述符。 with :: 将一个指针作为参数传递给一个临时分配的内存块
      throwSocketErrorIfMinus1Retry_ "getSockOrigDest" $
        c_getsockopt fd solIP soOrigDest ptr ptr_sz
      family <- peekByteOff ptr familyOffset
      case unpackFamily (fromIntegral (family :: CShort)) of --unpackFamily :: 将CInt转换为Family
        AF_UNIX -> parseSockAddrUnix ptr
        AF_INET -> parseSockAddrInet ptr
        AF_INET6 -> parseSockAddrInet6 ptr
        _ -> throwSocketError ("Unsupported socket address type: " ++ show family) -- 抛出与当前套接字错误对应的IOError。

getSockAddrFamily :: SockAddr -> Family

getSockAddrFamily (SockAddrUnix _) = AF_UNIX

getSockAddrFamily (SockAddrInet _ _) = AF_INET

getSockAddrFamily (SockAddrInet6 _ _ _ _) = AF_INET6

-- Read data from the first socket and send it to the second and third sockets. Forever.

forwardData :: Socket -> Socket -> Handle -> IO ()

forwardData srcSock destSock1 destSock2 = do
  msg <- recv srcSock 1024 --recv :: 从套接字接收数据。
  unless (DBS.null msg) $ do -- unless :: 取反。此处表示当msg不为空时执行do语句
    sendAll destSock1 msg
    DBS.hPut destSock2 msg
    forwardData srcSock destSock1 destSock2

-- Connect to the supplied socket's original destination. Then send data received from
-- one socket to the other, and vice-versa. When either socket is closed, close the other.

proxySocket :: Socket -> Handle -> Handle -> IO ()

proxySocket clientSock mitm1 mitm2 = do
  serverAddr <- getSockOrigDest clientSock
  let serverAI = defaultHints { addrSocketType = Stream, addrAddress = serverAddr, addrFamily = getSockAddrFamily serverAddr  }
  serverSock <- socket (addrFamily serverAI) (addrSocketType serverAI) (addrProtocol serverAI)
  connect serverSock serverAddr
  
  let closeSocks = \_ -> close clientSock >> close serverSock
  forkFinally (forwardData clientSock serverSock mitm1) closeSocks
  forkFinally (forwardData serverSock clientSock mitm2) closeSocks
  return ()

-- Start listening for client connections on the given port. When a connection is made,
-- transparently forward data to the original destination. Give a copy of the data sent
-- by the client to mitm1 and give a copy of the data sent by the server to mitm2.

runMITM :: String -> Handle -> Handle -> IO ()

runMITM port mitm1 mitm2 = do
  let proxyHints = defaultHints { addrSocketType = Stream, addrFlags = [AI_PASSIVE] }
  proxyAI:_ <- getAddrInfo (Just proxyHints) Nothing (Just port)
  proxySock <- socket (addrFamily proxyAI) (addrSocketType proxyAI) (addrProtocol proxyAI)
  bind proxySock (addrAddress proxyAI)
  listen proxySock 1
  forever $ do
    (clientSock, _) <- accept proxySock
    proxySocket clientSock mitm1 mitm2

-- Create a pair of handles to a common buffer. The first one is for reading, the second
-- for writing.

createPipeHandle :: IO (Handle, Handle) --Handle :: Haskell定义了从文件读取和写入字符的操作，由Handle类型的值表示。

createPipeHandle = do
  (a, b) <- createPipe --createPipe :: 函数创建一对连接的文件描述符。a :: 要读取的；b :: 要写入的
  ah <- fdToHandle a --将Fd转换为可与标准Haskell IO库一起使用的句柄
  bh <- fdToHandle b
  return (ah, bh)

-- Forever wait for connections. For each connection made, forward the data to the
-- original destination. Meanwhile, decrypt and decode the data passing through this
-- server.

main :: IO ()

main = do
  cmdArgs <- getArgs
  (clientReadEnd, clientWriteEnd) <- createPipeHandle
  (serverReadEnd, serverWriteEnd) <- createPipeHandle
  forkIO (analyzeData clientReadEnd initialXorKey) --forkIO :: 创建一个新线程来运行作为第一个参数传递的IO计算，并返回新创建线程的ThreadId。
  forkIO (analyzeData serverReadEnd initialXorKey)
  runMITM (head cmdArgs) clientWriteEnd serverWriteEnd

