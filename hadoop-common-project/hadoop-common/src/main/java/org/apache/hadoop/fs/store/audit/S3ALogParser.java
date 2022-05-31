/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.fs.store.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import org.apache.avro.Schema;
import org.apache.avro.file.DataFileWriter;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericDatumWriter;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.io.DatumWriter;
import org.apache.log4j.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class to help parse AWS S3 Logs.
 * see https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html
 *
 * Getting the regexp right is surprisingly hard; this class does it
 * explicitly and names each group in the process.
 * All group names are included in {@link #AWS_LOG_REGEXP_GROUPS} in the order
 * within the log entries.
 */

public class S3ALogParser {

    public S3ALogParser() {
    }

    private final Logger LOG = Logger.getLogger(S3ALogParser.class);

    /**
     * Simple entry: anything up to a space.
     * {@value}.
     */
    private static final String SIMPLE = "[^ ]*";

    /**
     * Date/Time. Everything within square braces.
     * {@value}.
     */
    private static final String DATETIME = "\\[(.*?)\\]";

    /**
     * A natural number or "-".
     * {@value}.
     */
    private static final String NUMBER = "(-|[0-9]*)";

    /**
     * A Quoted field or "-".
     * {@value}.
     */
    private static final String QUOTED = "(-|\"[^\"]*\")";

    /**
     * An entry in the regexp.
     *
     * @param name    name of the group
     * @param pattern pattern to use in the regexp
     * @return the pattern for the regexp
     */
    private static String e(String name, String pattern) {
        return String.format("(?<%s>%s) ", name, pattern);
    }

    /**
     * An entry in the regexp.
     *
     * @param name    name of the group
     * @param pattern pattern to use in the regexp
     * @return the pattern for the regexp
     */
    private static String eNoTrailing(String name, String pattern) {
        return String.format("(?<%s>%s)", name, pattern);
    }

    /**
     * Simple entry using the {@link #SIMPLE} pattern.
     *
     * @param name name of the element (for code clarity only)
     * @return the pattern for the regexp
     */
    private static String e(String name) {
        return e(name, SIMPLE);
    }

    /**
     * Quoted entry using the {@link #QUOTED} pattern.
     *
     * @param name name of the element (for code clarity only)
     * @return the pattern for the regexp
     */
    private static String q(String name) {
        return e(name, QUOTED);
    }

    /**
     * Log group {@value}.
     */
    public static final String OWNER_GROUP = "owner";

    /**
     * Log group {@value}.
     */
    public static final String BUCKET_GROUP = "bucket";

    /**
     * Log group {@value}.
     */
    public static final String TIMESTAMP_GROUP = "timestamp";

    /**
     * Log group {@value}.
     */
    public static final String REMOTEIP_GROUP = "remoteip";

    /**
     * Log group {@value}.
     */
    public static final String REQUESTER_GROUP = "requester";

    /**
     * Log group {@value}.
     */
    public static final String REQUESTID_GROUP = "requestid";

    /**
     * Log group {@value}.
     */
    public static final String VERB_GROUP = "verb";

    /**
     * Log group {@value}.
     */
    public static final String KEY_GROUP = "key";

    /**
     * Log group {@value}.
     */
    public static final String REQUESTURI_GROUP = "requesturi";

    /**
     * Log group {@value}.
     */
    public static final String HTTP_GROUP = "http";

    /**
     * Log group {@value}.
     */
    public static final String AWSERRORCODE_GROUP = "awserrorcode";

    /**
     * Log group {@value}.
     */
    public static final String BYTESSENT_GROUP = "bytessent";

    /**
     * Log group {@value}.
     */
    public static final String OBJECTSIZE_GROUP = "objectsize";

    /**
     * Log group {@value}.
     */
    public static final String TOTALTIME_GROUP = "totaltime";

    /**
     * Log group {@value}.
     */
    public static final String TURNAROUNDTIME_GROUP = "turnaroundtime";

    /**
     * Log group {@value}.
     */
    public static final String REFERRER_GROUP = "referrer";

    /**
     * Log group {@value}.
     */
    public static final String USERAGENT_GROUP = "useragent";

    /**
     * Log group {@value}.
     */
    public static final String VERSION_GROUP = "version";

    /**
     * Log group {@value}.
     */
    public static final String HOSTID_GROUP = "hostid";

    /**
     * Log group {@value}.
     */
    public static final String SIGV_GROUP = "sigv";

    /**
     * Log group {@value}.
     */
    public static final String CYPHER_GROUP = "cypher";

    /**
     * Log group {@value}.
     */
    public static final String AUTH_GROUP = "auth";

    /**
     * Log group {@value}.
     */
    public static final String ENDPOINT_GROUP = "endpoint";

    /**
     * Log group {@value}.
     */
    public static final String TLS_GROUP = "tls";

    /**
     * This is where anything at the tail of a log
     * entry ends up; it is null unless/until the AWS
     * logs are enhanced in future.
     * Value {@value}.
     */
    public static final String TAIL_GROUP = "tail";

    /**
     * Construct the log entry pattern.
     */
    public static final String LOG_ENTRY_REGEXP = ""
            + e(OWNER_GROUP)
            + e(BUCKET_GROUP)
            + e(TIMESTAMP_GROUP, DATETIME)
            + e(REMOTEIP_GROUP)
            + e(REQUESTER_GROUP)
            + e(REQUESTID_GROUP)
            + e(VERB_GROUP)
            + e(KEY_GROUP)
            + q(REQUESTURI_GROUP)
            + e(HTTP_GROUP, NUMBER)
            + e(AWSERRORCODE_GROUP)
            + e(BYTESSENT_GROUP)
            + e(OBJECTSIZE_GROUP)
            + e(TOTALTIME_GROUP)
            + e(TURNAROUNDTIME_GROUP)
            + q(REFERRER_GROUP)
            + q(USERAGENT_GROUP)
            + e(VERSION_GROUP)
            + e(HOSTID_GROUP)
            + e(SIGV_GROUP)
            + e(CYPHER_GROUP)
            + e(AUTH_GROUP)
            + e(ENDPOINT_GROUP)
            + eNoTrailing(TLS_GROUP, SIMPLE)
            + eNoTrailing(TAIL_GROUP, ".*") // anything which follows
            + "$"; // end of line

    /**
     * Groups in order.
     */
    private static final String[] GROUPS = {
            OWNER_GROUP,
            BUCKET_GROUP,
            TIMESTAMP_GROUP,
            REMOTEIP_GROUP,
            REQUESTER_GROUP,
            REQUESTID_GROUP,
            VERB_GROUP,
            KEY_GROUP,
            REQUESTURI_GROUP,
            HTTP_GROUP,
            AWSERRORCODE_GROUP,
            BYTESSENT_GROUP,
            OBJECTSIZE_GROUP,
            TOTALTIME_GROUP,
            TURNAROUNDTIME_GROUP,
            REFERRER_GROUP,
            USERAGENT_GROUP,
            VERSION_GROUP,
            HOSTID_GROUP,
            SIGV_GROUP,
            CYPHER_GROUP,
            AUTH_GROUP,
            ENDPOINT_GROUP,
            TLS_GROUP,
            TAIL_GROUP
    };

    /**
     * Ordered list of regular expression group names.
     */
    public static final List<String> AWS_LOG_REGEXP_GROUPS =
            Collections.unmodifiableList(Arrays.asList(GROUPS));

    /**
     * And the actual compiled pattern.
     */
    public static final Pattern LOG_ENTRY_PATTERN = Pattern.compile(
            LOG_ENTRY_REGEXP);

    /**
     * parseAuditLog method helps in parsing the audit log into key-value pairs using regular expression
     * @param singleAuditLog this is single audit log from merged audit log file
     * @return it returns a map i.e, auditLogMap which contains key-value pairs of a single audit log
     */
    public Map<String, String> parseAuditLog(String singleAuditLog){
        Map<String, String> auditLogMap = new HashMap<>();
        if(singleAuditLog == null || singleAuditLog.length() == 0) {
            LOG.info("This is an empty string or null string, expected a valid string to parse");
            return auditLogMap;
        }
        final Matcher matcher = LOG_ENTRY_PATTERN.matcher(singleAuditLog);
        matcher.matches();
        for(String key : AWS_LOG_REGEXP_GROUPS) {
            try {
                final String value = matcher.group(key);
                auditLogMap.put(key, value);
            } catch (IllegalStateException e) {
                LOG.info(e);
            }
        }
        LOG.info("Parsed audit log successfully");
        return auditLogMap;
    }

    /**
     * parseReferrerHeader method helps in parsing the http referrer header which is one of the key-value pair of audit log
     * @param referrerHeader this is the http referrer header of a particular audit log
     * @return it returns a map i.e, auditLogMap which contains key-value pairs of audit log as well as referrer header present in it
     */
    public Map<String, String> parseReferrerHeader(String referrerHeader) {
        Map<String, String> referrerHeaderMap = new HashMap<>();
        if( referrerHeader == null || referrerHeader.length() == 0) {
            LOG.info("This is an empty string or null string, expected a valid string to parse");
            return referrerHeaderMap;
        }
        int indexOfQuestionMark = referrerHeader.indexOf("?");
        String httpReferrer = referrerHeader.substring(indexOfQuestionMark + 1, referrerHeader.length() - 1);
        int lengthOfReferrer = httpReferrer.length();
        int start = 0;
        while (start < lengthOfReferrer) {
            int equals = httpReferrer.indexOf("=", start);
            // no match : break
            if (equals == -1) {
                break;
            }
            String key = httpReferrer.substring(start, equals);
            int end = httpReferrer.indexOf("&", equals);
            // or end of string
            if (end == -1) {
                end = lengthOfReferrer;
            }
            String value = httpReferrer.substring(equals + 1, end);
            referrerHeaderMap.put(key, value);
            start = end + 1;
        }
        LOG.info("Parsed referrer header successfully");
        return referrerHeaderMap;
    }

    /**
     * convertJsonToCsvFile method converts the json file into csv file
     * in which all key-value pairs of all audit logs are displayed as a table
     * @throws IOException
     */
    private void convertJsonToCsvFile() throws IOException {
        JsonNode jsonTree = new ObjectMapper().readTree(new File("Json.json"));
        JsonNode jsonTreeFields = new ObjectMapper().readTree(new File("JsonFields.json"));

        CsvSchema.Builder csvSchemaBuilder = CsvSchema.builder();
        JsonNode firstObject = jsonTreeFields.elements().next();
        firstObject.fieldNames().forEachRemaining(fieldName -> {csvSchemaBuilder.addColumn(fieldName);} );
        CsvSchema csvSchema = csvSchemaBuilder.build().withHeader();

        File csvFile = new File("CsvLogs.csv");
        CsvMapper csvMapper = new CsvMapper();
        csvMapper.writerFor(JsonNode.class)
                .with(csvSchema)
                .writeValue(csvFile, jsonTree);
        LOG.info("Successfully converted into CSV file");
    }

    /**
     * convertToAvroFile method converts list of maps into avro file by serializing
     * @param referrerHeaderList this is a list of maps which contains key-value pairs of only referrer header
     * @param auditLogList this is a list of maps which contains key-value pairs of audit log except referrer header
     * @throws IOException
     */
    private void convertToAvroFile(List<HashMap<String, String>> referrerHeaderList, List<HashMap<String, String>> auditLogList) throws IOException {

        //Instantiating the Schema.Parser class.
        Schema schema = new Schema.Parser().parse(new File("src/main/java/com/logs/schema.avsc"));

        DatumWriter<GenericRecord> datumWriter = new GenericDatumWriter<GenericRecord>(schema);

        DataFileWriter<GenericRecord> dataFileWriter = new DataFileWriter<GenericRecord>(datumWriter);
        File avroFile = new File("data.avro");
        dataFileWriter.create(schema, avroFile);

        ArrayList<String> longValues = new ArrayList<>(Arrays.asList("turnaroundtime", "bytessent", "objectsize", "totaltime"));
        int count = 0;

        //Insert data according to schema
        for(Map<String,String> auditLogMap : auditLogList) {
            //Instantiating the GenericRecord class
            GenericRecord genericRecord = new GenericData.Record(schema);

            for (Map.Entry<String,String> entry : auditLogMap.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue().trim();

                //if value == '-' and key is not in arraylist then put '-' or else '-1'
                //if key is in arraylist of long values then parse the long value
                //while parsing do it in try-catch block, in catch block need to log exception and set value as '-1'
                try {
                    if(longValues.contains(key)) {
                        if(value.equals("-")) {
                            genericRecord.put(key, null);
                        }
                        else {
                            genericRecord.put(key, Long.parseLong(value));
                        }
                    }
                    else {
                        genericRecord.put(key, value);
                    }
                }
                catch (Exception e) {
                    genericRecord.put(key, null);
                }
            }
            genericRecord.put("referrerMap", referrerHeaderList.get(count));
            dataFileWriter.append(genericRecord);
            count += 1;
        }
        dataFileWriter.close();

        LOG.info("Data successfully serialized and converted into Avro file");
    }

    /**
     * parseWholeAuditLog method will parse every audit log in merged audit log file into key-value pairs
     * and also converts the audit log data into csv file and avro file
     * @param auditLogsFilePath this is the path of audit log file
     * @return it returns a list of maps which contains key-value pairs of entire audit log including key-value pairs of referrer header
     * @throws IOException
     */
    public List<HashMap<String, String>> parseWholeAuditLog(String auditLogsFilePath) throws IOException {
        File auditLogFile = new File(auditLogsFilePath);
        List<HashMap<String, String>> entireAuditLogList = new ArrayList<>();
        List<HashMap<String, String>> referrerHeaderList = new ArrayList<>();
        List<HashMap<String, String>> auditLogList = new ArrayList<>();
        if(auditLogFile.isDirectory()) {
            LOG.info("This is a directory, expected a file to parse.");
            return entireAuditLogList;
        }

        LOG.info("File to be parsed : " + auditLogFile.getAbsolutePath());

        if (auditLogFile.length() != 0 && auditLogFile.isFile()) {
            File jsonFile = new File("Json.json");
            BufferedReader bufferedReader = new BufferedReader(new FileReader(auditLogFile));
            String singleAuditLog;
            ObjectMapper objectMapper = new ObjectMapper();

            //reads single audit log from merged audit log file and parse it
            while ((singleAuditLog = bufferedReader.readLine()) != null) {
                //parse audit log except referrer header
                Map<String, String> auditLogMap = parseAuditLog(singleAuditLog);

                String referrerHeader = auditLogMap.get("referrer");
                if (referrerHeader == null || referrerHeader.equals("-")) {
                    //LOG.info("Log didn't parsed : " + referrerHeader);
                    continue;
                }

                //parse only referrer header
                Map<String, String> referrerHeaderMap = parseReferrerHeader(referrerHeader);
                Map<String, String> entireAuditLogMap = new HashMap<>();
                entireAuditLogMap.putAll(auditLogMap);
                entireAuditLogMap.putAll(referrerHeaderMap);

                //adds every single map containing key-value pairs of single audit log into a list except referrer header key-value pairs
                //also adds every single map containing key-value pairs of referrer header into a list
                //and adds every single map containing key-value pairs of entire audit log into a list including referrer header key-value pairs
                auditLogList.add((HashMap<String, String>) auditLogMap);
                referrerHeaderList.add((HashMap<String, String>) referrerHeaderMap);
                entireAuditLogList.add((HashMap<String, String>) entireAuditLogMap);
            }
            LOG.info("Successfully parsed all logs from merged file");

            //this method is used to convert the list of maps into avro file for querying using hive and spark
            convertToAvroFile(referrerHeaderList, auditLogList);

            //adds list into json file which helps to convert key-value pairs into csv file
            objectMapper.writeValue(jsonFile, entireAuditLogList);

            //this method is used to convert the obtained json file into csv file
            convertJsonToCsvFile();
        }
        return entireAuditLogList;
    }
}
