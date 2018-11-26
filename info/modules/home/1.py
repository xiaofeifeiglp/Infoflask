
import re
import random
from datetime import datetime
from flask import current_app, request, abort, make_response, jsonify, session, g, redirect, url_for
from ihome.modules.api import api_blu
from ihome.libs.captcha.pic_captcha import captcha
from ihome import sr, db
# 访问静态文件
from ihome.utils import constants
from ihome.utils.constants import IMAGE_CODE_REDIS_EXPIRES, SMS_CODE_REDIS_EXPIRES, QINIU_DOMIN_PREFIX
from ihome.models import User, Area, House, Facility
from ihome.utils.response_code import RET, error_map
from ihome.utils.common import user_login_data, file_upload

# 获取图片验证码
@api_blu.route('/imagecode')  #/api/v1.0/imagecode
def get_img_code():
    # 获取参数
    cur_id = request.args.get("cur")  # img_code_id

    # 校验参数
    if not cur_id:
        return abort(403)

    # 生成图片验证码  图片名, 图片对应的文字, 图片二进制数据
    img_name, img_code, img_bytes = captcha.generate_captcha()

    # 保存验证码文字和图片key  Redis(设置过期时间 键值形式符合要求)
    try:
        sr.set("cur_" + cur_id, img_code, ex=IMAGE_CODE_REDIS_EXPIRES)
    except BaseException as e:
        current_app.logger.error(e)
        return abort(500)

    # 返回图片 自定义响应对象 设置content-type
    response = make_response(img_bytes)  # type: Response
    response.content_type = "image/jpeg"
    return response

# 获取短信验证码
@api_blu.route('/smscode', methods=['POST'])
def get_sms_code():
    # 获取参数
    image_code_id = request.json.get("image_code_id")
    image_code = request.json.get("image_code")
    mobile = request.json.get("mobile")
    # 校验参数
    if not all([image_code, image_code_id, mobile]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
    # 校验手机号格式
    if not re.match(r"1[345678]\d{9}$", mobile):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验图片验证码 根据图片key取出正确的图片验证码
    try:
        real_img_code = sr.get("cur_" + image_code_id)
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    if real_img_code != image_code.upper():  # 验证码错误
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 判断用户是否已存在  从数据库查询该用户数据
    try:
        user = User.query.filter_by(mobile=mobile).first()
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    if user:
        return jsonify(errno=RET.DATAEXIST, errmsg=error_map[RET.DATAEXIST])

    # 生成随机4位数字
    rand_num = "%04d" % random.randint(0, 9999)
    # 发送短信 使用模板id=1
    # response_code = CCP().send_template_sms(mobile, [rand_num, 5], 1)
    # if response_code != 0:
    #     return jsonify(errno=RET.THIRDERR, errmsg=error_map[RET.THIRDERR])

    # 保存短信验证码  设置过期时间, key:手机号 value:短信验证码
    try:
        sr.set("sms_code_id_" + mobile, rand_num, ex=SMS_CODE_REDIS_EXPIRES)
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    # 打印短信验证码
    current_app.logger.info("短信验证码为:%s" % rand_num)

    # json返回结果
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])

# 用户注册
@api_blu.route('/user', methods=['POST'])
def register():
    # 获取参数
    mobile = request.json.get("mobile")  # 手机号
    password = request.json.get("password")  # 密码
    phone_code = request.json.get("phonecode") # 短信验证码
    # 校验参数
    if not all([mobile, password, phone_code]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验手机号格式
    if not re.match(r"1[345678]\d{9}$", mobile):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验短信验证码
    try:
        real_sms_code = sr.get("sms_code_id_" + mobile)
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    if real_sms_code != phone_code:  # 验证码错误
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 保存用户数据
    try:
        user = User()
        user.mobile = mobile
        # 封装加密过程
        user.password = password
        # 记录最后登录时间
        user.last_login = datetime.now()

        user.name = mobile
        db.session.add(user)
        db.session.commit()
    except BaseException as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    # 对用户信息进行状态保持  只要保存用户记录的主键就可以查询出用户的所有数据
    session["user_id"] = user.id
    # json返回结果
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])

# 用户登录
@api_blu.route('/session', methods=['POST', 'GET', 'DELETE'])
def login():
    # 判断用户是否存在
    if request.method == 'GET':
        user_id = session.get('user_id')
        user = None
        if user_id:
            try:
                user = User.query.get(user_id)
            except BaseException as e:
                current_app.logger.error(e)
            data = {
                'name':user.mobile,
                'user_id':user_id
            }
            return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=data)
        return jsonify(errno=RET.SESSIONERR, errmsg=error_map[RET.PARAMERR])

    # 用户退出
    if request.method == 'DELETE':
        # 删除session中的数据  不设置默认值, key不存在, 会报错
        user_id = session.pop('user_id', None)
        return jsonify(error=RET.OK, errmsg=error_map[RET.OK])

    # 获取参数
    mobile = request.json.get("mobile")
    password = request.json.get("password")
    # 校验参数
    if not all([mobile, password]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验手机号格式
    if not re.match(r"1[345678]\d{9}$", mobile):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 获取到手机号对应的用户数据
    try:
        user = User.query.filter_by(mobile=mobile).first()
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    if not user:  # 判断用户是否存在
        return jsonify(errno=RET.NODATA, errmsg=error_map[RET.NODATA])

    # 校验密码
    if not user.check_passowrd(password):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 状态保持
    session["user_id"] = user.id

    # 记录最后登录时间  开启了SQLAlchemy的自动提交功能
    user.last_login = datetime.now()

    # json返回
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])

# 用户个人中心
@api_blu.route('/user')
@user_login_data  # 取出用户数据
def user_info():
    # 判断用户是否登录
    user = g.user
    if not user:  # 未登录
        return redirect(url_for("home.index"))
    data = user.to_dict()
    # json返回
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=data)

# 上传个人图像
@api_blu.route('/user/avatar', methods=['POST'])
@user_login_data # 取出用户数据
def pic_info():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问
    # POST处理
    file = request.files.get("avatar")
    try:
        img_bytes = file.read()  # 读取上传文件的二进制格式数据  bytes
        # 一般上传的文件会放到一个单独的文件服务器中进行管理  只需要获取文件名
        try:
            file_name = file_upload(img_bytes)
        except BaseException as e:
            current_app.logger.error(e)
            return jsonify(errno=RET.THIRDERR, errmsg=error_map[RET.THIRDERR])

        # 修改用户模型
        user.avatar_url = file_name

    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 需要回传用户信息, 以便前端来更新头像
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=user.to_dict())

# 用户名修改
@api_blu.route('/user/name', methods=['POST'])
@user_login_data
def user_append():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    # POST处理
    # 获取参数
    name = request.json.get("name")

    # 保存用户数据
    try:
        user.name = name
    except BaseException as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    # json返回
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])


# 获取用户实名信息
@api_blu.route('/user/auth', methods=['GET', 'POST'])
@user_login_data
def auth():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问
    if request.method == 'GET':
        data = user.to_auth_info()
        # json返回
        return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=data)

    # 获取参数
    real_name = request.json.get("real_name")
    id_card = request.json.get('id_card')

    # 校验参数
    if not all([real_name, id_card]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
    user.real_name = real_name
    user.id_card = id_card

    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])

# 城区列表
@api_blu.route('/areas', methods=['GET'])
@user_login_data
def areas():
    # 判断用户是否登录
    user = g.user
    if not user:  # 未登录
        return redirect(url_for("home.index"))
    area = Area.query.all()

    area_list = []
    try:
        area_list = [areas.to_dict() for areas in area]
    except BaseException as e:
        current_app.logger.error(e)
    # json返回
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=area_list)

# 我的房屋列表
@api_blu.route('/user/houses', methods=['GET'])
@user_login_data
def user_houses():
    # # 判断用户是否登录
    # user = g.user
    # if not user:  # 未登录
    #     return redirect(url_for("home.index"))
    # houses = House.query.all()
    #
    # house_list = []
    # try:
    #     house_list = [houses.to_dict() for houses in house_list]
    # except BaseException as e:
    #     current_app.logger.error(e)
    # # json返回
    # return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=house_list)

    user = g.user
    if not user:  # 判断用户登录
        return jsonify(errno=RET.SESSIONERR, errmsg=error_map[RET.PARAMERR])

    try:
        user.houses = House.query.all()
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    data = [houses.to_basic_dict() for houses in user.houses]

    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=data)

# 发布房源
@api_blu.route('/houses', methods=['POST'])
@user_login_data
def push_houses():
    user = g.user
    if not user:  # 判断用户登录
        return jsonify(errno=RET.SESSIONERR, errmsg=error_map[RET.PARAMERR])
    # 1.接收参数并且判空
    title = request.json.get('title')
    price = request.json.get('price')
    area_id = request.json.get('area_id')
    address = request.json.get('address')
    room_count =request.json.get('room_count')
    acreage = request.json.get('acreage')
    unit = request.json.get('unit')
    capacity = request.json.get('capacity')
    beds = request.json.get('beds')
    deposit = request.json.get('deposit')
    min_days = request.json.get('min_days')
    max_days = request.json.get('max_days')

    if not all([title, price, area_id, address, room_count, acreage, unit, capacity,
                beds, deposit, min_days, max_days]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
    # 2. 将参数的数据保存到新创建的house模型
    house = House()
    house.user_id = user.id
    house.title = title
    house.price = price
    house.area_id = area_id
    house.address = address
    house.room_count = room_count
    house.acreage = acreage
    house.unit = unit
    house.capacity = capacity
    house.beds = beds
    house.deposit = deposit
    house.min_days = min_days
    house.max_days = max_days


    # 获取到当期房屋的设施列表数组
    facilities = request.json.get('facility')
    if facilities:
        house.facilities = Facility.query.filter(Facility.id.in_(facilities)).all()
    # 保存house模型到数据库
    try:
        # 提交数据
        db.session.add(house)
        db.session.commit()
    except BaseException as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    data = {
        "house_id": house.id
    }
    # json返回结果
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=data)

# 上传房源图片
@api_blu.route('/houses/<int:house_id>/images',methods=['POST'])
@user_login_data
def houses_image(house_id):
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问
    # POST处理
    house_image = request.files.get('house_image')
    try:
        img_bytes = house_image.read()  # 读取上传文件的二进制格式数据  bytes
        # 一般上传的文件会放到一个单独的文件服务器中进行管理  只需要获取文件名
        try:
            file_name = file_upload(img_bytes)
        except BaseException as e:
            current_app.logger.error(e)
            return jsonify(errno=RET.THIRDERR, errmsg=error_map[RET.THIRDERR])

        house = House.query.get(house_id)
        if not house.index_image_url:
            house.index_image_url = file_name

        data = {'url':QINIU_DOMIN_PREFIX+file_name}

    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=data)

# 首页房屋推荐展示
@api_blu.route('/houses/index')
@user_login_data
def houses_index():
    try:
        houses = House.query.all()
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    data = [house.to_basic_dict() for house in houses]

    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=data)

# 房屋详情页面
@api_blu.route('/houses/<int:house_id>', methods=['GET'])
@user_login_data
def house_page(house_id):
    user = g.user
    if not house_id:
        return jsonify(errno=RET.PARAMERR, errmsg=RET.PARAMERR)
    try:
        house = House.query.get(house_id)
        data = {
            'house':house.to_full_dict()
        }
    except BaseException as e:
        current_app.logger.error('e')
        return abort(500)

    # json返回
    return jsonify(errno=RET.OK, errmsg=RET.OK, data=data)

# # 房屋数据搜索
# @api_blu.route('houses', methods=['GET'])
# @user_login_data
# def house_sogo():
#     # 获取参数
#     area_id = request.args.get("aid", "")
#     start_day = request.args.get("sd", "")
#     end_day = request.args.get("ed", "")
#     # 排序方式 booking(订单量), price-inc(低到高), price-des(高到低)
#     sort_key = request.args.get("sk", "")
#     page = request.args.get("p", "1")
#
#     # 页数格式转化
#     try:
#         page = int(page)
#     except BaseException as e:
#         current_app.logger.error(e)
#         return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
#
#     # 日期转化
#     try:
#         start_data = None
#         end_data = None
#         if start_day:
#             start_data = datetime.datetime.strftime(start_day, "%Y-%m-%d")
#         if end_day:
#             end_data = datetime.datetime.strftime(end_day, "%Y-%m-%d")
#
#         # 如果开始时间大于或者等于结束时间，就报错
#         if start_data and end_data:
#             assert start_data < end_data, Exception("开始时间大于结束时间")
#     except BaseException as e:
#         current_app.logger.error(e)
#         return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
#
#     # 从缓冲中取出房屋列表
#     try:
#         redis_key = "houses_%s_%s_%s_%s" % (start_day, end_day, area_id, sort_key)
#         response_data = sr.hget(redis_key, page)
#         if response_data:
#             return jsonify(errno=RET.Ok, errmsg=error_map[RET.Ok], data=eval(response_data))
#     except BaseException as e:
#         current_app.logger.error(e)
#         return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
#
#     # 查询数据
#     house_query = House.query.all()
#
#     filters = []
#     # 判断是否传入区域id
#
#     if area_id:
#         filters.append(House.area_id == area_id)
#
#     # 过滤已预定的房间
#     conflict_order = None
#     try:
#         if start_data and end_data:
#             conflict_order = Order.query.filter(Order.begin_date <= end_data, Order.end_date >= start_data).all()
#         elif start_data:
#             conflict_order = Order.query.filter(Order.end_date >= start_data).all()
#         elif end_data:
#             conflict_order = Order.query.filter(Order.begin_date >= end_data).all()
#     except BaseException as e:
#         current_app.logger.error(e)
#         return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])
#
#     if conflict_order:
#         # 取出冲突订单中的id
#         conflict_house_id = [order.house_id for order in conflict_order]
#         # 添加条件： 查询出房屋中不包括冲突订单中的房屋id
#         filters.append(not House.id.notin_(conflict_house_id))
#
#     # 根据筛选条件进行排序
#     if sort_key == "booking":
#         house_query = house_query.filter(*filters).order_by(House.order_count.desc())
#     elif sort_key == "price-inc":
#         house_query = house_query.filter(*filters).order_by(House.price.asc())
#     elif sort_key == "price-des":
#         house_query = house_query.filter(*filters).order_by(House.price.desc())
#     else:
#         house_query = house_query.filter(*filters).order_by(House.create_time.desc())
#
#
#         # 进行分页
#     paginate = house_query.paginate(int(page), constants.HOUSE_LIST_PAGE_CAPACITY, False)
#     # 取到当前页数据
#     houses = paginate.items
#     # 取到总页数
#     total_page = paginate.pages
#     # 将查询结果转化成字符串
#     houses_dict = []
#     for house in houses:
#         houses_dict.append(house.to_basic_dict())
#
#     response_data = {"total_page": total_page, "houses": houses_dict}
#     try:
#         redis_key = "houses_%s_%s_%s_%s" % (start_day, end_day, area_id, sort_key)
#         # 创建redis管道，支持多命令事物
#         pipe = sr.pipeline()
#         # 开启事物
#         pipe.multi()
#         # 设置数据
#         pipe.hset(redis_key, page, response_data)
#         # 设置过期时间
#         pipe.expire(redis_key, constants.HOUSE_LIST_REDIS_EXPIRES)
#         # 提交事物
#         pipe.execute()
#     except Exception as e:
#         current_app.logger.error(e)
#
#     return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=response_data)
#
# # # 评论订单
# # @api_blu.route('/orders/comment', methods = ['PUT'])
# # @user_login_data
# # def orders_comment():
# #     # 判断用户是否登录
# #     user = g.user
# #     if not user:
# #         return jsonify(errno=RET.SESSIONERR, errmsg=error_map[RET.SESSIONERR])
# #
# #     # 获取参数
# #     comment = request.json.get('comment')
# #     order_id = request.json.get('order_id')
# #
# #     # 校验参数
# #     if not all([comment, order_id]):
# #         return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
# #
# #     # 格式转换
# #     try:
# #         # comment_id = int(comment_id)
# #     except BaseException as e:
# #         current_app.logger.error(e)
# #         return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
# #
# #     # 查询并校验是否存在该评论
# #     try:
# #         # comment = Comment.query.get(comment_id)
# #     except BaseException as e:
# #         current_app.logger.error(e)
# #         return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])
# #
# #     if not comment:
# #         return jsonify(RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
# #
# #
# #     #json返回
# #     return jsonify(errno=RET.OK,errmsg=error_map[RET.OK])

