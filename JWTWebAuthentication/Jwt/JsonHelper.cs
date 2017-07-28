using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;

namespace JWTWebAuthentication
{
    /// <summary>
    /// json帮助类
    /// </summary>
    public class JsonHelper
    {
        /// <summary> 
        /// 对象转JSON 
        /// </summary> 
        /// <param name="obj">对象</param> 
        /// <param name="dateTimeFormat">时间序列化格式</param>
        /// <returns>JSON格式的字符串</returns> 
        public static string ObjectToJSON(object obj, string dateTimeFormat = "yyyy-MM-dd HH:mm:ss")
        {
            IsoDateTimeConverter timeFormat = new IsoDateTimeConverter();
            timeFormat.DateTimeFormat = dateTimeFormat;
            try
            {
                return JsonConvert.SerializeObject(obj, Formatting.Indented, timeFormat);
            }
            catch (Exception ex)
            {
                throw new Exception("JSONHelper.ObjectToJSON(): " + ex.Message);
            }
        }
        /// <summary>
        /// 对象转JSON
        /// </summary>
        /// <param name="obj">对象</param>
        /// <param name="PropSettings">属性设置</param>
        /// <returns>JSON格式的字符串</returns>
        public static string ObjectToJSON(object obj, JsonSerializerSettings PropSettings)
        {
            try
            {
                return JsonConvert.SerializeObject(obj, Formatting.Indented, PropSettings);
            }
            catch (Exception ex)
            {

                throw new Exception("JSONHelper.ObjectToJSON(): " + ex.Message);
            }
        }

        /// <summary> 
        /// JSON文本转对象,泛型方法 
        /// </summary> 
        /// <typeparam name="T">类型</typeparam> 
        /// <param name="jsonText">JSON文本</param> 
        /// <returns>指定类型的对象</returns> 
        public static T JSONToObject<T>(string jsonText)
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(jsonText);
            }
            catch (Exception ex)
            {
                throw new Exception("JsonHelper.JSONToObject(): " + ex.Message);
            }
        }

        /// <summary>
        /// JSON文本转对象集合,泛型方法 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="jsonText"></param>
        /// <returns></returns>
        public static List<T> JSONToObjects<T>(string jsonText)
        {
            try
            {
                return JsonConvert.DeserializeObject<List<T>>(jsonText);
            }
            catch (Exception ex)
            {
                throw new Exception("JsonHelper.JSONToObject(): " + ex.Message);
            }
        }
    }
}

