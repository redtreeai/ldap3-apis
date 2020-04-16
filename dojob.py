# -*- coding: utf-8 -*-
# @ Time   :  2020/1/9 9:36
# @ Author : Redtree
# @ File :  ldap_connect 
# @ Desc : ldap调试工具，待整理重构。


from ldap3 import Server, Connection, ALL, SUBTREE, ServerPool,NTLM,MODIFY_REPLACE


'''
LDAP(Light Directory Access Portocol)是轻量目录访问协议，基于X.500标准，支持TCP/IP。
LDAP目录以树状的层次结构来存储数据。每个目录记录都有标识名（Distinguished Name，简称DN），用来读取单个记录，

一般是这样的：
cn=username,ou=people,dc=test,dc=com
几个关键字的含义如下：
base dn：LDAP目录树的最顶部，也就是树的根，是上面的dc=test,dc=com部分，一般使用公司的域名，也可以写做o=test.com，前者更灵活一些。
dc:：Domain Component，域名部分。
ou：Organization Unit，组织单位，用于将数据区分开。
cn：Common Name，一般使用用户名。
uid：用户id，与cn的作用类似。
sn：Surname， 姓。
rdn：Relative dn，dn中与目录树的结构无关的部分，通常存在cn或者uid这个属性里。
所以上面的dn代表一条记录，代表一位在test.com公司people部门的用户username。
'''

BASE_DN = 'dc=citrix,dc=local'

#ldap 管理员登录校验,成功后返回链接对象
def ldap_admin_connect(username,password,LDAP_HOST):
    server = Server(LDAP_HOST, use_ssl=True,get_info=ALL)
    #conn = Connection(server)
    conn = Connection(server, username,password, auto_bind=True)
    #打印链接基础信息
    print(conn)
    '''
    connection几个参数解释（from官网）:
    SYNC: 同步模式，用户将在一次请求中获取回复数据
    ASYNC: 异步模式，用户发送请求后可稍后获取回复数据
    LDFI : LDAP数据目录的文本条目格式
    RESTARTABLE： 可重新启动：自动重新启动的同步连接。它将按指定的次数或永远重试操作。
    Lazy Connection: ，当您打开（）和bind（）时，不会执行任何操作。在执行有效的LDAP操作（添加、修改、删除、比较、修改DN、搜索、扩展）之前，
    这些操作将被延迟。如果在仍处于延迟状态时执行unbind（），则所有延迟操作都将取消，并且不会通过网络发送任何内容。当您的应用程序在知道是否需要有效操作之前打开连接时，
    这会很有帮助。
    REUSABLE: 可重用,一种异步策略，在内部打开到服务器的多个连接（或通过服务器池打开多个服务器），每个连接在不同的线程中

    '''
    connect_res = conn.result['description']
    #res = conn.search('dc=critrix,dc=local', '(objectclass=user)', attributes=['objectclass'])
    if connect_res=='success':
        print('授权登录成功')
        #after login-success , return the connection-object
        return True,conn
    else:
        print(conn.result)  # 查询失败的原因
        print(conn.entries)  # 查询到的数据
        return False,None


#同步用户表
def ldap_sync(conn):

    res = conn.search(
        search_base=BASE_DN,
        search_filter='(objectclass=user)',  # 查询所有用户
        search_scope=SUBTREE,
        attributes=['cn', 'sn', 'displayName', 'mail',
                    'sAMAccountName'] ) # cn用户中文名，sn姓，givenName名，mail邮件，sAMAccountName是账号

    if res:
        rdata = conn.response
        for entry in rdata:
            # dn = entry['dn']  # dn包含了ou信息dc信息等，在做域验登录时可以作为验证账号
            # dict_attr = entry['attributes']
            # cn = dict_attr['cn']
            # sn = dict_attr['sn']
            # givenName = dict_attr['givenName']
            # mail = dict_attr['mail']
            # sAMAccountName = dict_attr['sAMAccountName']
            # # 以下是从dn中的ou信息取第二个作为公司的部门名称信息
            print(entry['dn'])

#普通用户登录校验
def ldap_common_auth(username,password):
    server = Server(LDAP_HOST, use_ssl=True,get_info=ALL)
    try:
        conn2 = Connection(server, user=username, password=password,
                           check_names=True, lazy=False, raise_exceptions=False)
        conn2.bind()
        print(conn2.result)
        if conn2.result['description'] == 'success':  # 表示验证成功
            print(True)
        else:
            ERRORS = [('data 525','用户不存在'),
                      ('data 52e','密码或凭证无效'),
                      ('data 530','此时不允许登录'),
                      ('data 531','在此工作站上不允许登录'),
                      ('data 532','密码过期'),
                      ('data 533','账户禁用'),
                      ('data 701', '账户过期'),
                      ('data 773', '用户必须重置密码'),
                      ('data 775','用户账户锁定')]
            for er in ERRORS:
                if str(conn2.result).__contains__(er[0]):
                   print(er[1])
                   break
    except:
        print(False)





'''
组织相关操作
'''

#ladp添加组
def ldap_add_group(conn,group_name):
    #先添加一个组织
    add_group_res = conn.add('OU='+group_name+','+BASE_DN, object_class='OrganizationalUnit')
    if add_group_res==True:
        print('组:'+group_name+'添加成功')
    else:
        print('组:'+group_name+'添加失败')
        print(conn.result)
    return add_group_res

#ladps删除组
def ldap_delete_group(conn,group_name):
    #先添加一个组织
    delete_group_res = conn.delete('OU='+group_name+','+BASE_DN)
    if delete_group_res==True:
        print('组:'+group_name+'删除成功')
    else:
        print('组:'+group_name+'删除失败')
        print(conn.result)
    return delete_group_res


#查询所有组列表
def ldap_search_all_group(conn):
    sres = conn.search(BASE_DN,'(objectclass=OrganizationalUnit)')
    if sres==True:
        print('组织列表查询成功')
        ets = conn.entries
        for e in ets:
            print(e)
        return ets
    else:
        print('组织列表查询失败')
        return sres

#查询指定组所有用户
def ldap_search_group_user(conn,group_name):

    sres = conn.search('OU='+group_name+','+BASE_DN,'(objectclass=person)',attributes=['cn','displayName','mail'])
    if sres==True:
        print('组织:'+group_name+'用户列表查询成功')
        ets = conn.entries
        for e in ets:
            print(e)
        return ets
    else:
        print('组织:'+group_name+'用户列表查询失败')
        print(conn.result)
        return sres

#同步获取所有的域组用户数据
def ldap_sync_all_group_user(conn):

    #查询出所有的组
    sres = conn.search(BASE_DN,'(objectclass=OrganizationalUnit)',attributes=['OU'])
    group_list = []
    res_data = []
    if sres == True:
        print('组织列表查询成功')
        ets = conn.entries
        for e in ets:
            group_list.append(str(e['OU']))
        #根据组织列表查询所有用户的数据

        for g in group_list:
            gures = conn.search('OU='+g+','+BASE_DN,'(objectclass=person)',attributes=['cn','displayName','mail'])
            #同步组织用户成功
            if gures==True:
                ets = conn.entries
                for e in ets:
                    cuser = {'group_code':g,'group_name':g,'username':str(e['cn']),'nickname':str(e['displayName']),'email':str(e['mail'])}
                    print(cuser)
                    res_data.append(cuser)
        #全部同步成功后返回用户数据组
        return res_data
    else:
        print('组织列表查询失败,数据同步失败')
        return sres



#ladp添加用户
def ldap_add_group_user(conn,group_name,user_name):
    user_attributes = {
        'givenName':user_name, #姓名
        'displayName':user_name, #显示名称
        'mail':user_name+'@qq.com', #邮件
        'cn':user_name #用户名
    }
    add_user_res = conn.add('CN='+user_name+',OU='+group_name+','+BASE_DN, object_class='user',
                   attributes=user_attributes)
    # attributes支持的字段可以通过server.schema.object_classes['user']获取,这个字段的数据可以和web端做数据验证
    '''
    attributes支持的字段还需要另外封装
    '''
    if add_user_res == True:
        print('用户:'+user_name+'添加到' + group_name + '组成功')
    else:
        print('用户:'+user_name+'添加到' + group_name + '组失败')
        print(conn.result)
    return add_user_res


#ladp删除用户
def ldap_delete_group_user(conn,group_name,user_name):
    delete_user_res = conn.delete('CN='+user_name+',OU='+group_name+','+BASE_DN)
    '''
    attributes支持的字段还需要另外封装
    '''
    if delete_user_res == True:
        print('组:'+group_name+'/用户:'+user_name+'删除成功')
    else:
        print('组:'+group_name+'/用户:'+user_name+'删除失败')
        print(conn.result)
    return delete_user_res


#修改用户密码
def ldap_update_user_pwd(conn,group_name,user_name,password):
    # 修改用户密码需要在创建server对象是，use_ssl为True，且需要域服务器安装了Active Directionary证书服务
    update_res = conn.extend.microsoft.modify_password('CN='+user_name+',OU='+group_name+','+BASE_DN, new_password=password)
    if update_res==True:
        print('组:'+group_name+'用户:'+user_name+'密码重置成功')
    else:
        print('组:'+group_name+'用户:'+user_name+'密码重置失败')
        print(conn.result)
    return update_res


#启用或禁用账号
def ldap_update_user_status(conn,group_name,user_name,status_code):
    #1为永久启用，其他为永久禁用
    action = '启用'
    if status_code==1:
        update_res = conn.modify('CN=' + user_name + ',OU=' + group_name + ',' + BASE_DN,{'userAccountControl': [(MODIFY_REPLACE, ['66048'])]})
    else:
        action='禁用'
        update_res = conn.modify('CN=' + user_name + ',OU=' + group_name + ',' + BASE_DN,{'userAccountControl': [(MODIFY_REPLACE, ['66050'])]})

    if update_res == True:
        print('组:' + group_name + '用户:' + user_name + '账号'+action+'成功')
    else:
        print('组:' + group_name + '用户:' + user_name + '账号'+action+'失败')
        print(conn.result)
    return update_res


#无证书状态下的操作
#登录校验
LDAP_HOST = '192.168.19.05'
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = '123456..'

flag,conn = ldap_admin_connect(ADMIN_USERNAME,ADMIN_PASSWORD,LDAP_HOST)
if flag==False:
    print('ldap登录授权失败')
else:
    print('ldap登录授权成功')
    #同步用户表
    #ldap_sync(conn)
    #执行对应的测试操作
    #添加用户组
    #ldap_add_group(conn,'manteia')
    #添加用户（默认禁用）
    #ldap_add_group_user(conn,'manteia','lilanqi')
    #添加用户
    #ldap_add_group_user(conn,'manteia','test3')
    #重置用户密码
    #ldap_update_user_pwd(conn,group_name='manteia',user_name='chs',password='123456')
    #删除用户
    #ldap_delete_group_user(conn,group_name='manteia',user_name='redtree')
    #删除组，组内用户需为空方可删除，没有做关联删除
    #ldap_delete_group(conn,group_name='manteia')
    #查询组织列表
    #ldap_search_all_group(conn)
    #查询指定组织用户列表
    #ldap_search_group_user(conn,'manteia')
    #普通用户登录校验
    #ldap_common_auth('ctxadmin','abc123..')
    #启用或者禁用账户
    #ldap_update_user_status(conn,'manteia','chs',1)
    #同步获取所有组织用户数据
    #r = ldap_sync_all_group_user(conn)
    #print(r)
conn.unbind()
print('解除端口绑定')