//package hw9.repository;
//
//import hw9.DBConnection.DBConnectionManager;
//import hw9.domain.Users.Users;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.stereotype.Repository;
//
//import java.sql.Connection;
//import java.sql.PreparedStatement;
//import java.sql.ResultSet;
//import java.sql.SQLException;
//import java.util.ArrayList;
//
//@Slf4j
//@Repository
//public class UserRepository {
//
//    // 새로운 사용자 생성하는 함수: Create
//    public Users CreateUsers(Users newUser) throws SQLException {
//        Connection connection = null;
//        PreparedStatement statement = null;
//
//        // sql문 입력
//        String sql = "INSERT INTO `users`(`user_id` ,`user_pw`, `user_name`) VALUES(?, ?, ?)";
//
//        try{
//            connection = DBConnectionManager.getConnection();
//            statement = connection.prepareStatement(sql);
//
//            statement.setString(1, newUser.getUser_id()); // id값 입력
//            statement.setString(2, newUser.getUser_pw()); // pw값 입력
//            statement.setString(3, newUser.getUser_name()); // name값 입력
//
//            statement.executeUpdate(); // 쿼리 실행
//            return newUser; // 반환
//
//        } catch (SQLException e) {
//
//            log.error("repo.CreateUsers error={}", e); // Exception 발생 시 로그
//            throw e;
//
//        } finally {
//            closeResources(connection, statement, null); // 자원 반환
//        }
//    }
//
//    // 모든 사용자 검색 함수
//    public ArrayList<Users> findAllUsers() throws SQLException{
//        Connection connection = null;
//        PreparedStatement statement = null;
//        ResultSet resultset = null;
//
//        // 모든 사용자를 선택하는 쿼리문 작성
//        String sql = "select * from users";
//
//        try {
//            connection = DBConnectionManager.getConnection();
//            statement = connection.prepareStatement(sql);
//
//            resultset = statement.executeQuery(); // 쿼리 실행
//            ArrayList<Users> resUsers = new ArrayList<>(); // 여러개의 값을 리턴해야하기 때문에 ArrayList 활용
//            while(resultset.next()){
//                Users user_tmp = new Users(); // 임시 객체 생성
//                user_tmp.setUser_id(resultset.getString("user_id")); // set user_id
//                user_tmp.setUser_pw(resultset.getString("user_pw")); // set user_pw
//                user_tmp.setUser_name(resultset.getString("user_name")); // set user_name
//                resUsers.add(user_tmp); // resUsers add
//            }
//
//            return resUsers; // resUsers 반환
//        } catch (SQLException e){
//            log.error("repo.findAllUsers={}", e); // Exception 발생 시 로그
//            throw e;
//        } finally {
//            closeResources(connection, statement, resultset); // 자원 반환
//        }
//    }
//
//    // 특정 사용자 검색 함수
//    public Users findUsers(String id) throws SQLException{
//        Connection connection = null;
//        PreparedStatement statement = null;
//        ResultSet resultset = null;
//
//        // 특정 사용자를 선택하는 쿼리문 작성
//        String sql = "select * from users where user_id = ?";
//
//        try {
//            connection = DBConnectionManager.getConnection();
//            statement = connection.prepareStatement(sql);
//
//            statement.setString(1, id);
//
//            resultset = statement.executeQuery(); // 쿼리 실행
//            Users resUsers = new Users(); // 리턴 객체 생성
//            while(resultset.next()){
//                resUsers.setUser_id(resultset.getString("user_id")); // set user_id
//                resUsers.setUser_pw(resultset.getString("user_pw")); // set user_pw
//                resUsers.setUser_name(resultset.getString("user_name")); // set user_name
//            }
//
//            return resUsers; // resUsers 반환
//        } catch (SQLException e){
//            log.error("repo.findUsers={}", e); // Exception 발생 시 로그
//            throw e;
//        } finally {
//            closeResources(connection, statement, resultset); // 자원 반환
//        }
//    }
//
//    // 특정 사용자를 삭제하는 함수
//    public int DeleteUser(String id) throws SQLException {
//        Connection connection = null;
//        PreparedStatement statement = null;
//
//        // sql문 입력
//        String sql = "DELETE FROM `users` where user_id = ?";
//
//        try{
//            connection = DBConnectionManager.getConnection();
//            statement = connection.prepareStatement(sql);
//
//            statement.setString(1, id); // id값 입력
//
//            statement.executeUpdate(); // 쿼리 실행
//            return 1; // 반환
//
//        } catch (SQLException e) {
//
//            log.error("repo.DeleteUsers error={}", e); // Exception 발생 시 로그
//            throw e;
//
//        } finally {
//            closeResources(connection, statement, null); // 자원 반환
//        }
//    }
//
//    public Users UpdateUser(String id, Users TargetUser) throws SQLException {
//        Connection connection = null;
//        PreparedStatement statement = null;
//
//        String sql = "Update `users` set user_name = ?, user_pw = ? where user_id = ?";
//        // sql문 입력
//
//        try{
//            connection = DBConnectionManager.getConnection();
//            statement = connection.prepareStatement(sql);
//
//            statement.setString(1, TargetUser.getUser_name());
//            statement.setString(2, TargetUser.getUser_pw());
//            statement.setString(3, id); // id값 입력
//
//            statement.executeUpdate(); // 쿼리 실행
//            return TargetUser; // 반환
//
//        } catch (SQLException e) {
//
//            log.error("repo.UpdateUsers error={}", e); // Exception 발생 시 로그
//            throw e;
//
//        } finally {
//            closeResources(connection, statement, null); // 자원 반환
//        }
//    }
//
//    // 자원 반환하는 함수
//    // 반드시 ResultSet, PreparedStatement, Connection 순서대로 반환해야한다!
//    private void closeResources(Connection connection, PreparedStatement statement, ResultSet resultset) {
//        if (resultset != null){ // resultset 객체가 있는 경우
//            try{
//                resultset.close();
//            } catch (SQLException e) {
//                log.error("resultset close error");
//            }
//        }
//
//        if (statement != null){ // statement 객체가 있는 경우
//            try{
//                statement.close();
//            } catch (SQLException e) {
//                log.error("statement close error");
//            }
//        }
//
//        if (connection != null){ // connection 객체가 있는 경우
//            try{
//                connection.close();
//            } catch (SQLException e) {
//                log.error("connection close error");
//            }
//        }
//
//    }
//
//}
