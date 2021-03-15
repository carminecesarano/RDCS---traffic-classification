#!/bin/bash

#usage function
display_usage() {
	echo -e "\nUSAGE: './RDCS.sh [option] [data path]'"
	echo -e "\nTry './RDCS.sh --help' for more information.\n"
	}

tie_function() {
	for D in "$1"/* ; do
		echo -n "."
    		if [ -d "${D}" ]; then
        			TIE -a ndping_1.0 -r ${D}/traffic.pcap -d output/traccia$i > /dev/null
							cp ${D}/strace.log output/traccia$i
							cp ${D}/traffic.pcap output/traccia$i
							rm output/traccia$i/report.txt
	        		((i++))
        fi
	done
}

#report variables
export num_biflussi=0
export validati=0
export non_validati=0
export non_validabili=0
export not_tcp=0
export classificati=0
export non_classificati=0

# if less than one arguments supplied, display usage
	if [ $# -ne 2 ]; then
	# check whether user had supplied -h or --help . If yes display usage
		if [[ ( $1 == "--help") ||  $1 == "-h" ]]; then
			echo "******************************************************************"
			echo "* RDCS 1.0 [Reti di Calcolatori Script]"
			echo "* Computer Engineering, Computer Network I, AA 2017/2018"
			echo "* University of Napoli Federico II"
			echo "* by Carmine Cesarano, mat. N46/2883"
			echo "* This program was written in the scope of Computer Network exam."
			echo "* The open source TIE tool, developed by the computer network group"
			echo "* COMICS, was used in this script."
			echo "******************************************************************"
			echo -e "\nUSAGE:"
			echo "	./RDCS.sh [option] [data path]"
			echo -e "\nOPTIONS"
			echo "	-t 	execute TIE command and classify pcap trace"
			echo "	-v 	validation of classification output file"
			echo "	-s   refining of classification. Use it on result of -v option"

			exit 1
		fi
		display_usage
		exit 1
	fi

# execute TIE command and generate output files
	if [[ ( $1 == "-t" ) &&  "$#" -eq 2 ]]; then
		i=1
		DIRECTORY="output"
		if [ -d "$DIRECTORY" ]; then
			echo "Alert. $DIRECTORY dir already exist. File can be rewrite"
			echo "Continue?[Y/N]"
	  		read answer

			if [ "$answer" == "Y" ]; then
				echo -n "Processing"
				tie_function $2
				echo -e '\nSuccessfull.'
			elif [ "$answer" == "N" ]; then
				echo "Alert. Program will be aborted"
				exit 1
			fi
		elif [ ! -d "$DIRECTORY" ]; then
			mkdir $DIRECTORY
			echo -n "Processing"
		   	tie_function $2
			echo -e '\nSuccessfull.'
		fi
	fi

# evaluation of classification output file
	if [[ ( $1 == "-v" ) && "$#" -eq 2 ]]; then
		START_TIME=$SECONDS
		echo -n "Processing"
		for D in "$2"/* ; do
			echo -n "."
 		      	if [ -d "${D}" ]; then

				#clear file
				cat ${D}/strace.log | cut -d ' ' -f 1,6,7 | grep com. > ${D}/straceOut.log
				sed '1,11d;$d' ${D}/class.tie | cut -f 2,3,4,5,6,15,16 > ${D}/classOut.tie

				#match addressess/ports between logs and classification files
				while IFS=$'\t' read src_ind dst_ind proto src_port dst_port app_details confidence; do
					export num_biflussi=$((num_biflussi+1))

					if [[ $confidence == "100" ]]; then
						export classificati=$((classificati+1))

						if [ "$proto" -eq "6" ]; then
							cat ${D}/straceOut.log | grep "$src_ind:$src_port" | grep "$dst_ind:$port_ind" | grep TCP | cut -d ' ' -f1 >> ${D}/tempTCP
							if [[ -s ${D}/tempTCP ]]; then
								app_log=($(sort -u ${D}/tempTCP))

								#write "OK" if classification is validated or "N" otherwise
								if [[ $app_log == *"${app_details,,}"* ]]; then
									echo -e "$app_log""\tOK" >> ${D}/tempApp
									export validati=$((validati+1))
								elif [[ ($app_details == "Google") && ($app_log == "com.android.vending") ]]; then
									echo -e "$app_log""\tOK" >> ${D}/tempApp
									export validati=$((validati+1))
								else
									echo -e "$app_log""\tN" >> ${D}/tempApp
									export non_validati=$((non_validati+1))
								fi
							else
								#write "NV" if classification is not validable
								echo -e "-""\tNV" >> ${D}/tempApp
								export non_validabili=$((non_validabili+1))
							fi;
							rm ${D}/tempTCP
						else
							#if protocol isn't TCP
							echo -e "-""\tNOT_TCP" >> ${D}/tempApp
							export not_tcp=$((not_tcp+1))
						fi
					else
						export non_classificati=$((non_classificati+1))
						if [[ ! -z $app_log ]]; then
							echo -e "$app_log""\tNC" >> ${D}/tempApp
						else
							echo -e "-""\tNC" >> ${D}/tempApp
						fi
					fi

				done <${D}/classOut.tie

				#remove header
				cp ${D}/class.tie ${D}/class.gt.tie
				sed '1,11d' -i ${D}/class.gt.tie

				#add a column for the validation of classification
				paste ${D}/class.gt.tie ${D}/tempApp | pr -t > ${D}/temp.gt.tie
				rm ${D}/class.gt.tie

				#re-add header
				sed '1,11!d' ${D}/class.tie > ${D}/header
				mv ${D}/temp.gt.tie ${D}/class.gt.tie
				cat ${D}/class.gt.tie >> ${D}/header
				rm ${D}/class.gt.tie
				mv ${D}/header ${D}/class.gt.tie

				#remove temp files
				rm ${D}/tempApp
				rm ${D}/strace.log
				rm ${D}/straceOut.log
				rm ${D}/classOut.tie
			fi
		done
		ELAPSED_TIME=$(($SECONDS - $START_TIME))

		#global validation report
		echo -e "\n\nVALIDATION REPORT" >> report
		echo -e "tempo di elaborazione:\t$(($ELAPSED_TIME/60)) min $(($ELAPSED_TIME%60)) sec\n" >> report
		echo -e "biflussi processati:\t\t$num_biflussi" >> report
		echo -e "biflussi classificati:\t\t$classificati" >> report
		echo -e "biflussi non classificati:\t$non_classificati\n" >> report
		echo -e "biflussi OK:\t\t\t$validati" >> report
		echo -e "biflussi N:\t\t\t$non_validati" >> report
		echo -e "biflussi NV:\t\t\t$non_validabili" >> report
		echo -e "biflussi NOT_TCP:\t\t$not_tcp" >> report
		echo -e "\nOK:\t la classificazione della tupla è stata validata con esito" >> report
		echo -e "\t positivo confrontando con il file di log." >> report
		echo -e "\nN:\t le informazioni fornite dal file di log non sono sufficienti" >> report
		echo -e "\t per validare la classificazione della tupla." >> report
		echo -e "\nNV:\t la classificazione non è validabile tramite il file di log" >> report
		echo -e "\t in cui non vi sono riferimenti alla tupla." >> report
		echo -e "\nNOT_TPC: biflussi con protocollo non TCP non validabili tramite log.\n" >> report
		cat report

		echo -e '\nSuccessfull.'
	fi

# refining of classification
	if [[ ( $1 == "-r" ) && "$#" -eq 2 ]]; then
		START_TIME=$SECONDS
		echo -n "Processing"
		for D in "$2"/* ; do
			echo -n "."
 		      	if [ -d "${D}" ]; then

				#clear file
				sed '1,11d;$d' ${D}/class.gt.tie | cut -f 2,3,4,5,6,11,15,17,18 > ${D}/tempClass

				#analyze pcap trace
				tshark -r ${D}/traffic.pcap -T fields -e frame.time_epoch -e dns.qry.name -e dns.a -e ip.geoip.asnum -e ssl.handshake.extensions_server_name -E separator="/t" -E occurrence=f > ${D}/tempTraffic

				while IFS=$'\t' read src_ip dst_ip proto src_port dst_port time app_details app_log val; do
					export num_biflussi=$((num_biflussi+1))

					#refine classification only if validation is not "OK"
					if [ "$val" != "OK" ]; then

						dns=$(cat ${D}/tempTraffic | grep "$time" | cut -f2)
						ssl=$(cat ${D}/tempTraffic | grep "$time" | cut -f 5)
						net_name=$(cat ${D}/tempTraffic | grep "$time" | cut -f 4 | cut -d' ' -f2,3,4 )

						#WHOIS
					#	if [ "$src_ip" == "192.168.20.105" ]; then
					#		whois=$(whois "$dst_ip" | grep -i "orgname\|org-name\|descr" | head -n1 | cut -c 17-80)
					#	else
					#		whois=$(whois "$src_ip" | grep -i "orgname\|org-name\|descr" | head -n1 | cut -c 17-80)
					#	fi

						#DIG
						if [ "$src_ip" == "192.168.20.105" ]; then
							dig=$(dig +short @8.8.8.8 -x "$dst_ip" | head -n1)
							if [[ -z $dig ]]; then
								dig="-"
							fi
						else
							dig=$(dig +short @8.8.8.8 -x "$src_ip" | head -n1)
							if [[ -z $dig ]]; then
								dig="-"
							fi
						fi

						touch occ_netname
						touch occ_netnameNC
						touch occ_dns
						touch occ_ads

						if [[ ! -z $net_name ]]; then
							#if manual classification match TIE classification (net_name==app_details)
							if echo "$net_name" | grep -q "$app_details"; then
								echo -e "$net_name""\t$dig""\t$dns""\t$ssl" >> ${D}/tempGeo
								#increment number of valid classification
								export validati=$((validati+1))
							else
								echo -e "$net_name""\t$dig""\t$dns""\t$ssl" >> ${D}/tempGeo
							fi
							#occurrence report
							echo -e "$dns" >> occ_dns
							echo "$net_name" >> occ_netname
							if [ "$val" == "NC" ]; then echo "$net_name" >> occ_netnameNC; fi
						else
							echo -e "NOTFOUND\t\t\t" >> ${D}/tempGeo
							if [ "$val" == "NC" ]; then echo "NOTFOUND" >> occ_netnameNC; fi
							echo "NOTFOUND" >> occ_netname
						fi
					else
						#Manual classification unnecessary. Already classified by log
						echo -e "-\t\t\t" >> ${D}/tempGeo
						echo "$app_details" >> occ_netname
					fi

					#add a classification for unclassified biflow
					if [ "$val" == "NC" ]; then
						if [ $app_log == "com.android.vending" ]; then
							new_classification="Google"
						else
							new_classification=$(echo $app_log | cut -d'.' -f2)
						fi
						echo "${new_classification^}" >> ${D}/newclass
					else
						new_classification=$app_details
						echo "$new_classification" >> ${D}/newclass
					fi

					#ads report
					echo -e "${new_classification^}""\t$net_name" >> occ_ads


				done <${D}/tempClass

				#remove header
				cp ${D}/class.gt.tie ${D}/temp.gt.tie
				sed '1,11d' -i ${D}/temp.gt.tie

				#add a column for the validation of classification
				paste ${D}/temp.gt.tie ${D}/tempGeo ${D}/newclass | pr -t > ${D}/class.gt.tie


				#re-add header and re-format file
				sed '1,10!d' ${D}/class.tie > ${D}/header0
				sed '11!d' ${D}/class.tie > ${D}/header
				sed -i '1s/$/\tapp_log\tvalidation\tnet_name\tname_resolution\tdns_request\tssl\tnew_classification/' ${D}/header
				cat ${D}/class.gt.tie | column -t -n -s $'\t' >> ${D}/header
				cat ${D}/header >> ${D}/header0
				mv ${D}/header0 ${D}/class.gt.tie

				#remove temp file
				rm ${D}/header
				rm ${D}/temp.gt.tie
				rm ${D}/tempClass
				rm ${D}/tempGeo
				rm ${D}/tempTraffic
				rm ${D}/newclass

			fi
		done
		ELAPSED_TIME=$(($SECONDS - $START_TIME))

		#global refining report
		echo -e "\nREFINING REPORT" >> report1
		echo -e "tempo di elaborazione:\t$(($ELAPSED_TIME/60)) min $(($ELAPSED_TIME%60)) sec" >> report1
		echo -e "biflussi VAL:\t\t$validati" >> report1
		sed -i "13r report1" report
		echo -e "VAL:\t classificazioni precedentemente non validate con i file di log" >> report
		echo -e "\t e ora validate tramite l'analisi dei file pcap" >> report
		echo -e "\nNET OCCURRENCES" >> report
		cat occ_netname | cut -d',' -f1 | sort | uniq -c >> report
		echo -e "\nNET OCCURRENCES FOR NC BIFLOW" >> report
		cat occ_netnameNC | cut -f1 | sort | uniq -c >> report
		echo -e "\n TRAFFIC ORIGIN" >> report
		cat occ_ads | sort | uniq -c | sed '1i\\tapp\tnet' >> report
		echo -e "\nHOST NAME OCCURRENCES IN DNS REQUEST" >> report
		cat occ_dns | sort | uniq -c >> report
		rm occ_netname
		rm occ_netnameNC
		rm occ_dns
		rm occ_ads
		sed -i '1i '"$(date -u)"'' report
		head -n33 report
		mv report RDCS_report
		rm report1

		echo -e '\nSuccessfull.'
	fi
