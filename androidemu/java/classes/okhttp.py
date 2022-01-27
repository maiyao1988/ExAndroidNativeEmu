from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def, JavaMethodDef


class Buffer(metaclass=JavaClassDef, jvm_name='okio/Buffer'):
    def __init__(self):
        pass
    #
    
    @java_method_def(name='<init>', signature='()V', native=False)
    def init(self, emu):
        pass
    #

    @java_method_def(name='writeString', args_list=["jstring", "jobject"], signature='(Ljava/lang/String;Ljava/nio/charset/Charset;)Lokio/Buffer;', native=False)
    def writeString(self, emu, string, charset):
        raise NotImplementedError()
    #


    @java_method_def(name='readByteArray', signature='()[B', native=False)
    def readByteArray(self, emu):
        raise NotImplementedError()
        pass
    #


    @java_method_def(name='read', args_list=["jobject"], signature='([B)I', native=False)
    def read(self, emu, array):
        raise NotImplementedError()
        pass
    #


    @java_method_def(name='close', signature='()V', native=False)
    def close(self, emu):
        pass
    #

    @java_method_def(name='clone', signature='()Lokio/Buffer;', native=False)
    def clone(self, emu):
        raise NotImplementedError()
        pass
    #
#


class ResponseBody(metaclass=JavaClassDef, jvm_name='okhttp3/ResponseBody'):
    def __init__(self):
        pass
    #

    @java_method_def(name='string', signature='()Ljava/lang/String;', native=False)
    def string(self, emu):
        raise NotImplementedError()
    #
#

class Builder(metaclass=JavaClassDef, jvm_name='okhttp3/Request$Builder'):
    def __init__(self):
        pass
    #

    @java_method_def(name='header', args_list=["jstring", "jstring"], signature='(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;', native=False)
    def header(self, emu, skey, svalue):
        raise NotImplementedError()
    #

    @java_method_def(name='build', signature='()Lokhttp3/Request;', native=False)
    def build(self, emu, skey, svalue):
        raise NotImplementedError()
    #
#

class HttpUrl(metaclass=JavaClassDef, jvm_name='okhttp3/HttpUrl'):
    def __init__(self, url_string):
        pass
    #

    @java_method_def(name='encodedPath', signature='()Ljava/lang/String;', native=False)
    def encodedPath(self, emu):
        raise NotImplementedError()
    #

    @java_method_def(name='encodedQuery', signature='()Ljava/lang/String;', native=False)
    def encodedQuery(self, emu):
        raise NotImplementedError()
    #
#

class RequestBody(metaclass=JavaClassDef, jvm_name='okhttp3/RequestBody'):
    def __init__(self):
        pass
    #

    @java_method_def(name='writeTo', args_list=["jobject"], signature='(Lokio/BufferedSink;)V', native=False)
    def writeTo(self, emu, buffer):
        raise NotImplementedError()
    #
    
#


class Headers(metaclass=JavaClassDef, jvm_name='okhttp3/Headers'):
    def __init__(self):
        pass
    #

    @java_method_def(name='values', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/util/List;', native=False)
    def values(self, emu, jstr):
        raise NotImplementedError()
    #

    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        raise NotImplementedError()
    #

    @java_method_def(name='name', args_list=["jint"], signature='(I)Ljava/lang/String;', native=False)
    def name(self, emu, i):
        raise NotImplementedError()
    #

    @java_method_def(name='value', args_list=["jint"], signature='(I)Ljava/lang/String;', native=False)
    def value(self, emu, i):
        raise NotImplementedError()
    #
#


class Request(metaclass=JavaClassDef, jvm_name='okhttp3/Request'):
    def __init__(self, url_path, headers):
        self.__url_object = HttpUrl(url_path)
        self.__headers_object = Headers(headers)
    #

    @java_method_def(name='url', signature='()Lokhttp3/HttpUrl;', native=False)
    def url(self, emu):
        return self.__url_object
    #

    @java_method_def(name='body', signature='()Lokhttp3/RequestBody;', native=False)
    def body(self, emu):
        raise NotImplementedError()
    #

    @java_method_def(name='headers', signature='()Lokhttp3/Headers;', native=False)
    def headers(self, emu):
        return self.__headers_object
    #


    @java_method_def(name='newBuilder', signature='()Lokhttp3/Request$Builder;', native=False)
    def newBuilder(self, emu):
        raise NotImplementedError()
    #
#

class Response(metaclass=JavaClassDef, jvm_name='okhttp3/Response'):
    def __init__(self):
        pass
    #
    
    @java_method_def(name='code', signature='()I', native=False)
    def code(self, emu):
        raise NotImplementedError()
    #

    @java_method_def(name='body', signature='()Lokhttp3/ResponseBody;', native=False)
    def body(self, emu):
        raise NotImplementedError()
    #

    @java_method_def(name='close', signature='()V', native=False)
    def close(self, emu):
        raise NotImplementedError()
    #

    @java_method_def(name='header', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
    def header(self, emu, skey):
        raise NotImplementedError()
    #
#

class Chain(metaclass=JavaClassDef, jvm_name='okhttp3/Interceptor$Chain'):
    def __init__(self, req):
        self.__req = req
        self.__req_after_proceed = None
    #


    @java_method_def(name='request', signature='()Lokhttp3/Request;', native=False)
    def request(self, emu):
        return self.__req
    #


    @java_method_def(name='proceed', args_list=["jobject"], signature='(Lokhttp3/Request;)Lokhttp3/Response;', native=False)
    def proceed(self, emu, req):
        self.__req_after_proceed = req
        #FIXME 暂时不知道这个Resonse返回的含义,暂时返回空Response应该没什么问题
        return Response()
    #

    def get_proceed_request():
        return self.__req_after_proceed
    #
#