import random
import re
from datetime import datetime

from flask import request, abort, current_app, make_response, Response, jsonify, session

from info import sr, db
from info.lib.captcha.pic_captcha import captcha
from info.lib.yuntongxun.sms import CCP
from info.models import User
from info.modules.passport import passport_blu


# 获取图片验证码
from info.utils.response_code import RET, error_map


@passport_blu.route('/get_img_code')
def get_img_code():
    # 获取参数
    img_code_id = request.args.get("img_code_id")

    # 校验参数
    if not img_code_id:
        return abort(403)  # 拒绝访问

    # 生成图片验证码
    img_name, img_text, img_bytes = captcha.generate_captcha()

    # 保存验证码文字和图片key  redis  设置过期时间
    try:
        sr.set("img_code_id_" + img_code_id, img_text, ex=300)
    except BaseException as e:
        current_app.logger.error(e)  # 记录错误信息
        return abort(500)

    # 自定义响应对象  设置响应头的content-type为image/jpeg
    response = make_response(img_bytes)  # type: Response
    response.content_type = "image/jpeg"
    return response


# 获取短信验证码
@passport_blu.route('/get_sms_code', methods=['POST'])
def get_sms_code():
    # 获取参数
    img_code_id = request.json.get("img_code_id")
    img_code = request.json.get("img_code")
    mobile = request.json.get("mobile")
    # 校验参数
    if not all([img_code_id, img_code, mobile]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验手机格式
    if not re.match(r"1[35678]\d{9}$", mobile):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验图片验证码  根据图片key取出真实的验证码文字
    try:
        real_img_code = sr.get("img_code_id_" + img_code_id)
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    if real_img_code != img_code.upper():
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 判断用户是否存在
    user = User.query.filter_by(mobile=mobile).first()
    if user:
        return jsonify(errno=RET.DATAEXIST, errmsg=error_map[RET.DATAEXIST])

    # 生成随机短信验证码
    rand_num = "%04d" % random.randint(0, 9999)
    # 打印验证码
    current_app.logger.info("短信验证码为:%s" % rand_num)

    # 发送短信
    # response_code = CCP().send_template_sms(mobile, [rand_num, 5], 1)
    # if response_code != 0:
    #     return jsonify(errno=RET.THIRDERR, errmsg=error_map[RET.THIRDERR])

    # 保存短信验证码  设置过期时间
    try:
        sr.set("sms_code_id_" + mobile, rand_num, ex=60)
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    # 返回json结果
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])

# 用户注册
@passport_blu.route('/register', methods=['POST'])
def register():
    # 获取参数
    mobile = request.json.get("mobile")
    password = request.json.get("password")
    sms_code = request.json.get("sms_code")
    # 校验参数
    if not all([mobile, password, sms_code]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验手机格式
    if not re.match(r"1[35678]\d{9}$", mobile):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验短信验证码  先根据手机号取出短信验证码
    try:
        real_sms_code = sr.get("sms_code_id_" + mobile)
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])
    
    if sms_code != real_sms_code:  # 验证码错误
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
    
    # 保存用户信息
    try:
        user = User()
        user.mobile = mobile
        user.nick_name = mobile
        # 使用@property属性来封装加密过程
        user.password = password
        # 记录用户的最后登录时间(日期对象)
        user.last_login = datetime.now()

        db.session.add(user)
        db.session.commit()
    except BaseException as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    # 状态保持(免密码登录)  只需要保存用户id即可
    session["user_id"] = user.id

    # 返回json结果
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])


# 用户登录
@passport_blu.route('/login', methods=['POST'])
def login():
    # 获取参数
    mobile = request.json.get("mobile")
    password = request.json.get("password")
    # 校验参数
    if not all([mobile, password]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 校验手机格式
    if not re.match(r"1[35678]\d{9}$", mobile):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 根据手机号查询用户信息
    try:
        user = User.query.filter_by(mobile=mobile).first()
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg=error_map[RET.DBERR])

    if not user:  # 没有该用户
        return jsonify(errno=RET.NODATA, errmsg=error_map[RET.NODATA])

    # 校验密码
    if not user.check_password(password):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 记录最后登录时间  使用sqlalchemy自动提交
    user.last_login = datetime.now()
    # 状态保持
    session["user_id"] = user.id

    # 返回json
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])


# 退出登录
@passport_blu.route('/logout')
def logout():
    # 删除session中的user_id
    session.pop("user_id", None)
    session.pop("is_admin", None)
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])