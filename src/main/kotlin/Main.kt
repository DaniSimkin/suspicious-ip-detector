
fun main(args: Array<String>) {
    
    val ipv4List = listOf("10.50.30.7/8", "135.50.30.7/3", "192.168.0.1/24", "192.168.0.1/23")
    val ipv6List = listOf("2002::1234:abcd:ffff:c0a8:101/63", "2001:4860:4860::8888/32")
    val suspiciousIPCheckerForV4 = SuspiciousIPChecker(ipv4List,"4")
    val suspiciousIPCheckerForV6 = SuspiciousIPChecker(ipv6List, "6")
    var ipAddressDefaultV4 : String = "12.168.0.13"
    var ipAddressDefaultV6 : String = "2002::1234:abcd:ffff:c0a8:101"

    try {

        if(suspiciousIPCheckerForV4.validateAddress(ipAddressDefaultV4) ||
            suspiciousIPCheckerForV6.validateAddress(ipAddressDefaultV6)) {
            println("Is Allowed: V4- " + suspiciousIPCheckerForV4.isAllowed(ipAddressDefaultV4))
            println("Is Allowed: V6- " + suspiciousIPCheckerForV6.isAllowed(ipAddressDefaultV6))
        }
        else{
            println("one or more of the IP addresses have been entered incorrectly - please enter ip's in the correct pattern")
        }
    }catch (e: java.lang.Exception){
        println("An Invalid Address had most likely been entered or the versions had been tempered with, please try again")
    }

}

class SuspiciousIPChecker(originalArrayList: List<String>, version: String) {

    private val versionDefault: String = version
    private val originalList: List<String> = originalArrayList
    private val afterAndOperationList: List<ULong> = originalArrayList.map { ip -> ipWithCidrToBinLong(ip,versionDefault)}

    fun validateAddress(address: String): Boolean {
        val ipRegex = Regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\$")
        return ipRegex.matches(address)
    }

    fun printOriginalList() {
        println(afterAndOperationList)
    }

    // using Long here because int can hold up 2^32 - 1 number which is 10 digits long
    // I have here 32 bits at least
    fun ipWithCidrToBinLong(ip: String, version: String): ULong {
        var binSize: Int = 0
        var delim: String = ""
        when (version) {
            "4" -> {
                binSize = 32
                delim = "."
            }
            "6" -> {
                binSize = 64
                delim = ":"
            }
        }
        val parts = ip.split("/")
        val maskLen = parts[1]
        val ipParts = parts[0].split(delim)

        var ipAsLong: ULong = 0u
        for (part in ipParts) {
            ipAsLong = ipAsLong shl 8
            if (!part.isEmpty())
                when (version) {
                    "4" -> ipAsLong += part.toUInt()
                    "6" -> ipAsLong += Integer.valueOf(part.uppercase(), 16).toUInt()
                }

        }

        var mask: ULong = 0u
        for (i in 1..binSize) {
            mask = mask shl 1
            when (i) {
                in 1..maskLen.toInt() -> mask += 1u
            }
        }
        //println("retVal:\t" + ipAsLong.toString(2).padStart(binSize, '0'))
        //println("mask: \t" + mask.toString(2).padStart(binSize, '0'))
        return ipAsLong and mask
    }

    fun isAllowed(ip: String): Boolean {
        var cidr: String;
        // I can safely iterate over which List I prefer since they are Immutable(don't change during run time)
        // So no matter which format of data I have there - it will always have the same number of elements in order
       for(index in  0..originalList.size - 1 ) {
          cidr = "/" + originalList[index].split("/")[1]
          if(ipWithCidrToBinLong(ip + cidr, versionDefault) == afterAndOperationList[index]){
              return false
          }
       }
        return true
    }
}

