#coding: utf-8

import subprocess, sys, os
import threading, time, datetime
import logging, argparse
import shutil
import zipfile

logging.basicConfig(level = logging.INFO, format='%(asctime)s - %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')


def execShellDaemon(cmd):
    '''
    async
    '''
    return subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

def execShell(cmd, t=120):
    '''
    sync
    haskey('d') == success, only cmd success, should check output
    '''
    ret = {}
    try:
        p = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, timeout=t)
        
        if p.returncode == 0:
            try:
                ret['d'] = p.stdout.decode('utf-8')
            except:
                ret['d'] = p.stdout.decode('gbk')
        else:
            try:
                ret['e'] = p.stderr.decode('utf-8')
            except:
                ret['e'] = p.stderr.decode('gbk')
            
    except subprocess.TimeoutExpired:
        ret['e'] = 'timeout'
    except Exception as e:
        logging.error('subprocess '+str(e))

    return ret

def getPkgList(pkg):
    if os.path.isfile(pkg):
        try:
            with open(pkg, 'r') as f:
                pkgs = f.read().split('\n')
        except Exception as e:
            #logging.info(str(e))
            return []
    elif pkg:
        pkgs = pkg.split(',')
    out = []
    for p in pkgs:
        if p:
            out.append(p.strip())
    return out


class APuller(object):
    def __init__(self, did):
        self._adb = 'adb'
        self._did = did
        self._devicepkg = []
        self._curdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '')
        self._dirapps = os.path.join(self._curdir, 'apps', '')
        self._dirappstmp = os.path.join(self._dirapps, 'tmp', '')
        self._dirinter = os.path.join(self._curdir, 'inter', '')
        self._androidver = ''
        self._blacklist = [
            'com.android.settings',
            'com.topjohnwu.magisk',
            'com.speedsoftware.rootexplorer',
            'org.proxydroid',
            'android'
        ]

        self._init()
    
    def _init(self):
        if not self.checkOnline(self._did):
            sys.exit()
        if self._did:
            self._adb = 'adb -s '+self._did+' '
        self._devicepkg = self.getDevicePkgs()
        try:
            os.mkdir(self._dirapps)
        except:
            pass
        try:
            os.mkdir(self._dirappstmp)
        except:
            pass

        self._androidver = self.getAndroidVer()

        cmd = self._adb + ' shell  "mkdir /data/local/tmp/appstarter"'
        ret = execShell(cmd)

    def checkOnline(self, deviceid=''):
        devices = execShell('adb devices -l').get('d').split('\n')
        ret = [d for d in devices if d.find('device ') != -1]
        dids = [d.split()[0] for d in ret]
        if deviceid:
            if deviceid in dids:
                return True
            else:
                logging.error('Device id error')
                logging.error(execShell('adb devices -l').get('d'))
                return False
        else:
            if len(dids) == 0:
                logging.error('No device')
                return False
            elif len(dids) == 1:
                return True
            elif len(dids) > 1:
                logging.error('More than one device, please set -s deviceid')
                return False

    def getAndroidVer(self):
        cmd = self._adb + ' shell getprop ro.build.version.release'
        ret = execShell(cmd)
        if 'd' in ret.keys():
            logging.info('android version '+ret.get('d').rstrip('\n'))
            return ret.get('d').rstrip('\n')

    def getDevicePkgs(self):
        ret = execShell(self._adb + ' shell pm list packages')
        pkgs = []
        if 'e' not in ret.keys():
            dt = ret.get('d').split('\n')
            for p in dt:
                p = p.strip()
                if p:
                    pkgs.append(p.split(':')[1])
        else:
            logging.error(ret.get('e'))
        return pkgs
    
    def isDexExist(self, apk):
        #系统app将dex存在其他位置，也可能不存在dex
        zipf = zipfile.ZipFile(apk)
        if 'classes.dex' in zipf.namelist():
            return True
        return False

    def getPhonemodel(self):
        cmd = self._adb + ' shell "getprop ro.com.google.clientidbase"'
        ret = execShell(cmd)
        out = ret.get('d')
        if out:
            return out.strip()

    def assembleAPP(self, path, sp, vdextool, cdextool):
        d = os.path.dirname(path)
        n = os.path.basename(d)+'.vdex'
        dt = d+'/oat/arm/'+n
        cmd = self._adb + ' shell "ls  '+d+'/oat/arm/'+n+' "'
        ret = execShell(cmd)
        if 'No such file' in str(ret) :
            cmd = self._adb + ' shell "ls  '+d+'/oat/arm64/'+n+' "'
            ret1 = execShell(cmd)
            if 'No such file' not in str(ret1):
                dt = d+'/oat/arm64/'+n
            else:
                logging.error('dex and vdex not exist')
                return
        
        #在手机上转换，跨平台
        logging.info('using vdexExtractor')
        cmd = self._adb + ' shell  "/data/local/tmp/'+vdextool+'  -f -i  '+dt+' -o /data/local/tmp/appstarter/"'
        ret = execShell(cmd)

        # multi cdex?
        cmd = self._adb + ' shell "ls /data/local/tmp/appstarter/'+os.path.basename(d)+'_classes*.cdex | wc"'
        ret = execShell(cmd)
        count = 0
        if 'd' in ret.keys():
            count = int(ret.get('d').rstrip('\n').split()[0])
        cdex = False
        for i in range(0, count):
            #cdex
            cdex = True
            logging.info('using compact-dex-converter')
            t = str(i + 1)
            if t == '1':
                t = ''
            cmd = self._adb + ' shell  "/data/local/tmp/'+cdextool+' /data/local/tmp/appstarter/'+os.path.basename(d)+'_classes'+t+'.cdex"'
            ret = execShell(cmd)

        if count == 0:
            #no cdex
            cmd = self._adb + ' shell "ls /data/local/tmp/appstarter/'+os.path.basename(d)+'_classes*.dex"'
            ret = execShell(cmd)
            if 'No such file' in str(ret):
                logging.error('vdex to dex/cdex error')

        cmd = self._adb + ' pull  /data/local/tmp/appstarter/ '+self._dirappstmp
        ret = execShell(cmd)
        cmd = self._adb + ' shell  "rm -f  /data/local/tmp/appstarter/* "'
        ret = execShell(cmd)

        zipf = zipfile.ZipFile(sp+'.apk', 'a')
        #多个dex
        ndex = False
        for f in os.listdir(self._dirappstmp+'appstarter'):
            if cdex and '.new' in f and os.path.basename(d)+'_classes' in f:
                # com.miui.fm_classes.cdex.new
                zipf.write(os.path.join(self._dirappstmp+'appstarter', f), f.split('_')[1].split('.')[0]+'.dex')
                ndex = True

            elif not cdex and '.dex' in f and os.path.basename(d)+'_classes' in f:
                # com.miui.fm_classes.dex
                zipf.write(os.path.join(self._dirappstmp+'appstarter', f), f.split('_')[1])
        zipf.close()
        if not ndex and cdex:
            logging.error('cdex to dex error')
        logging.info('assemble apk done')
        shutil.rmtree(self._dirappstmp+'appstarter')
        
    def pull(self, pkg):
        pkgs = getPkgList(pkg)
        
        cdextool = 'cdex_converter64'
        vdextool = 'vdexExtractor64'
        arm64 = True
        cmd = self._adb + ' shell "getprop ro.product.cpu.abi"'
        ret = execShell(cmd)
        if 'd' in ret.keys() and 'arm64' not in ret.get('d'):
            arm64 = False

        #android9出现cdex
        if self._androidver >= '9':
            if not arm64:
                cdextool = 'cdex_converter32'
            cmd = self._adb + ' shell "ls /data/local/tmp/'+cdextool+' "'
            ret = execShell(cmd)
            if 'No such file' in str(ret):
                if not os.path.isfile(self._dirinter+cdextool): 
                    logging.info('从android9+ 手机下载app，需要compact-dex-converter')
                    logging.error('先下载{} 链接: https://pan.baidu.com/s/1VMKyJ3n4ubiXeqICNatzYw 提取码: q8fk 保存到inter目录下'.format(cdextool))
                else:
                    cmd = self._adb + ' push '+self._dirinter+cdextool+' /data/local/tmp/'
                    ret = execShell(cmd)
                    if 'd' in ret.keys():
                        logging.info('push compact-dex-converter success')
                    cmd = self._adb + ' shell "su -c \' chmod +x /data/local/tmp/'+cdextool+' \' " '
                    ret = execShell(cmd)

        #android7.0出现vdex，在手机上执行转换
        elif self._androidver >= '7':
            if not arm64:
                vdextool = 'vdexExtractor32'
            cmd = self._adb + ' shell "ls /data/local/tmp/'+vdextool+' "'
            ret = execShell(cmd)
            if 'No such file' in str(ret):
                if not os.path.isfile(self._dirinter+vdextool):
                    logging.info('从android7+ 手机下载app，需要vdexExtractor')
                    logging.error('先下载{} 链接: https://pan.baidu.com/s/1VMKyJ3n4ubiXeqICNatzYw 提取码: q8fk 保存到inter目录下'.format(vdextool))
                else:
                    cmd = self._adb + ' push '+self._dirinter+vdextool+' /data/local/tmp/'
                    ret = execShell(cmd)
                    if 'd' in ret.keys():
                        logging.info('push vdexExtractor success')
                    cmd = self._adb + ' shell "su -c \' chmod +x /data/local/tmp/'+vdextool+' \' " '
                    ret = execShell(cmd)

        else:
            note = '''
            #android6's odex，need framework/baksmali
            #adb pull /system/framework inter/
            #adb pull /system/priv-app/CalendarProvider/oat/arm64/CalendarProvider.odex apps/
            #java -jar inter/baksmali-2.4.0.jar x apps/CalendarProvider.odex -d inter/framework/ -b inter/framework/arm64/boot.oat -o apps/out
            #java -jar inter/smali-2.4.0.jar a apps/out/ -o apps/CalendarProvider.dex
            '''
            logging.error('android version: {} not supported {}'.format(self._androidver, note))
        
        #huawei phone can not pull apk from /data/app
        self.phonemodel = self.getPhonemodel()
        
        for p in pkgs:
            if p not in self._devicepkg:
                logging.error(p+' not installed')
                continue
            if not self.checkOnline(self._did):
                logging.error('Device offline')
                return
            
            logging.info('=='+p)
            try:
                sp = self._dirapps+p
                #without version check
                # if os.path.isfile(sp+'.apk'):
                #     continue
                
                cmd = self._adb + ' shell "pm path  '+p+'"'
                ret = execShell(cmd)
                # multiple apk?
                if 'd' in ret.keys() and ret.get('d'):
                    apkpath = ret.get('d').split('\n')[0].split(':')[1].strip()
                    logging.info('Pull from device')
                    if 'huawei' in self.phonemodel:
                        cmd = self._adb + ' shell "cp '+apkpath+' /sdcard/tmp.apk"'
                        ret = execShell(cmd)
                        apkpath = '/sdcard/tmp.apk'
                    cmd = self._adb + ' pull '+apkpath+' '+sp
                    ret = execShell(cmd)
                    if 'd' in ret.keys():
                        shutil.move(sp, sp+'.apk')
                        if not self.isDexExist(sp+'.apk') and self._androidver >= '7':
                            self.assembleAPP(apkpath, sp, vdextool, cdextool)
                    else:
                        logging.error('pull error'+ret.get('e')+apkpath)
                else:
                    logging.error('device has no '+p)

            except KeyboardInterrupt:
                raise KeyboardInterrupt

            except Exception as e:
                import traceback
                traceback.print_exc()
                logging.error(str(e))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pull app from device', formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''
    python3 apuller.py -p com.xiaomi.music
    python3 apuller.py -P plist.txt
    ''')
    parser.add_argument("-p", "--pkg", type=str, help="single app")
    parser.add_argument("-P", "--plist", type=str, help="multiple apps")
    parser.add_argument("-s", "--did", type=str, help="device ID")

    
    args = parser.parse_args()
    pkg = args.pkg
    plist = args.plist
    did = args.did

    try:
        if pkg:
            apuller = APuller(did)
            apuller.pull(pkg)
        
        elif plist:
            apuller = APuller(did)
            apuller.pull(plist)

        else:
            parser.print_help()
    except KeyboardInterrupt:
        logging.info('Ctrl+C')
